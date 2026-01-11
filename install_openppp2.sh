#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"

DEFAULT_IMAGE="ghcr.io/lucifer988/openppp2:latest"
DEFAULT_BASE_CFG_URL="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

COMPOSE_KIND="" # "docker compose" or "docker-compose"

need_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
has_systemd() { [[ -d /run/systemd/system ]] && need_cmd systemctl; }

die() { echo -e "[!]\t$*" >&2; exit 1; }
info() { echo -e "[*]\t$*"; }
warn() { echo -e "[!]\t$*" >&2; }

prompt() {
  local __var="$1" __msg="$2" __def="${3:-}"
  local __val=""
  if [[ -n "$__def" ]]; then
    read -r -p "$__msg [$__def]: " __val
    __val="${__val:-$__def}"
  else
    read -r -p "$__msg: " __val
  fi
  printf -v "$__var" "%s" "$__val"
}

compose() {
  if [[ "$COMPOSE_KIND" == "docker compose" ]]; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

detect_compose() {
  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"
    return 0
  fi
  if need_cmd docker-compose; then
    COMPOSE_KIND="docker-compose"
    return 0
  fi
  COMPOSE_KIND=""
  return 1
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  # 尽量避免配置文件交互（不强制覆盖）
  apt-get update -y
  apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "$@"
}

curl_retry() {
  # 减少网络抖动导致的失败概率
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 --max-time 120 "$@"
}

ensure_basic_tools() {
  # jq/iproute2 用于 JSON 修改与网卡/IP 自动检测
  apt_install ca-certificates curl jq iproute2 gnupg >/dev/null 2>&1 || true
  need_cmd curl || die "curl 未安装成功，请检查 apt 源/网络"
  need_cmd jq || die "jq 未安装成功，请检查 apt 源/网络"
  need_cmd ip || die "iproute2 未安装成功，请检查 apt 源/网络"
}

start_docker_daemon() {
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now containerd >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start containerd >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service containerd start >/dev/null 2>&1 || true
    service docker start >/dev/null 2>&1 || true
  fi
}

docker_daemon_ok() {
  need_cmd docker || return 1
  docker info >/dev/null 2>&1
}

ensure_docker_stack() {
  ensure_basic_tools

  if ! need_cmd docker; then
    info "检测到未安装 Docker，开始安装（Debian/Ubuntu 默认仓库）..."
    apt_install containerd docker.io iptables >/dev/null 2>&1 || true
    start_docker_daemon
  fi

  if ! docker_daemon_ok; then
    info "Docker 已安装但 daemon 未就绪，尝试启动/修复..."
    # 再补装一次常见依赖（不会重复安装）
    apt_install containerd docker.io iptables >/dev/null 2>&1 || true
    start_docker_daemon
  fi

  if ! docker_daemon_ok; then
    warn "Docker daemon 仍不可用。下面自动输出诊断信息："
    if has_systemd; then
      systemctl status docker --no-pager -l || true
      echo "-----"
      journalctl -u docker -n 200 --no-pager || true
    else
      service docker status || true
    fi
    echo
    die "Docker daemon 不可用（常见原因：OpenVZ/LXC 不支持 Docker；或内核/权限限制导致 overlay2/iptables 不可用）。"
  fi

  # 选择 compose：优先 docker compose（plugin），避免与 docker-compose 包冲突
  if ! detect_compose; then
    # 先尝试安装 plugin（很多系统有这个包）
    apt_install docker-compose-plugin >/dev/null 2>&1 || true
  fi

  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"
  else
    # plugin 不可用时才考虑 docker-compose
    # 关键：如果系统已有 docker-compose-plugin，就不要装 docker-compose（Debian trixie 会冲突）
    if dpkg -s docker-compose-plugin >/dev/null 2>&1; then
      : # 避免冲突
    else
      apt_install docker-compose >/dev/null 2>&1 || true
    fi
    detect_compose || die "未检测到 compose（docker compose 或 docker-compose）。请安装后重试。"
  fi

  info "使用 compose：${COMPOSE_KIND}"
}

gen_guid() {
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

# Returns: "LAN_IP|DEV|GW"
detect_net() {
  local out lan dev gw
  out="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
  lan="$(awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")"
  dev="$(awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")"
  gw="$(awk '/via/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$out")"

  # fallback：默认路由
  if [[ -z "$dev" ]]; then dev="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')" || true; fi
  if [[ -z "$gw"  ]]; then gw="$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')" || true; fi
  if [[ -z "$lan" ]]; then
    # 从默认网卡取一个 IPv4
    if [[ -n "${dev:-}" ]]; then
      lan="$(ip -4 addr show "$dev" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)" || true
    fi
  fi

  echo "${lan:-}|${dev:-}|${gw:-}"
}

download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"
  info "下载基准配置..."
  curl_retry -sS "$url" -o appsettings.base.json
}

enable_ip_forward_host() {
  info "开启宿主机 IPv4 转发（client 模式需要）..."
  if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    cat >/etc/sysctl.d/99-openppp2.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null 2>&1 || true
  else
    warn "宿主机 sysctl 写入失败（可能权限受限）。client 模式可能无法正常转发。"
    warn "你可以手动执行：sysctl -w net.ipv4.ip_forward=1"
  fi
}

compose_header() {
  # docker-compose(v1) 对没有 version 的文件兼容性差一些
  # docker compose(v2) 有 version 会警告但不影响使用
  if [[ "$COMPOSE_KIND" == "docker-compose" ]]; then
    echo 'version: "3.8"'
  fi
}

write_compose_server() {
  local image="$1"
  {
    compose_header
    cat <<EOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    volumes:
      - ./appsettings.json:/opt/openppp2/appsettings.json:ro
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
EOF
  } >"$COMPOSE_FILE"
}

write_compose_client() {
  local image="$1" nic="$2" gw="$3"
  {
    compose_header
    cat <<EOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
    volumes:
      - ./appsettings.json:/opt/openppp2/appsettings.json:ro
      - ./ip.txt:/opt/openppp2/ip.txt:ro
      - ./dns-rules.txt:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=appsettings.json"
      - "--tun-host=yes"
      - "--tun-ip=10.0.0.2"
      - "--tun-gw=10.0.0.1"
      - "--tun-mask=30"
      - "--tun-vnet=yes"
      - "--tun-flash=no"
      - "--tun-static=no"
      - "--block-quic=yes"
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
      - "--tun-mux=4"
      - "--tun-mux-acceleration=3"
      - "--tun-ssmt=4/st"
      - "--dns=8.8.8.8"
      - "--bypass-iplist-nic=${nic}"
      - "--bypass-iplist-ngw"
      - "${gw}"
EOF
  } >"$COMPOSE_FILE"
}

setup_systemd_weekly_update() {
  echo
  info "设置 systemd 每周自动更新（拉最新镜像并重启 openppp2）"
  echo "    例子：Sun *-*-* 03:00:00  表示每周日 03:00 执行"
  echo "         Mon *-*-* 04:30:00  表示每周一 04:30 执行"
  local oncal
  prompt oncal "请输入 OnCalendar（按周）表达式" "${DEFAULT_ONCAL}"

  cat >/usr/local/bin/openppp2-update.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

"${dc[@]}" pull openppp2
"${dc[@]}" up -d --remove-orphans openppp2
EOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'EOF'
[Unit]
Description=Update openppp2 container image
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
EOF

  cat >/etc/systemd/system/openppp2-update.timer <<EOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${oncal}
Persistent=true
Unit=openppp2-update.service

[Install]
WantedBy=timers.target
EOF

  if has_systemd; then
    systemctl daemon-reload
    systemctl enable --now openppp2-update.timer
  else
    warn "你的环境没有 systemd，无法启用 timer。你可以改用 crontab 定时执行 /usr/local/bin/openppp2-update.sh"
  fi
}

health_check() {
  # 简单检查容器是否存活，若没起来给出提示
  if ! docker ps --format '{{.Names}}' | grep -qx 'openppp2'; then
    warn "openppp2 容器未处于运行状态。请查看日志："
    echo "    cd ${APP_DIR} && ${COMPOSE_KIND} logs --tail=200 openppp2"
    echo
    warn "如果你看到 io_uring_queue_init: Operation not permitted："
    warn " - 说明镜像里是 io-uring 版本，在某些内核/安全策略下会被限制。"
    warn " - 你需要换用 non-io-uring 的 openppp2 版本重新构建镜像，或改用对应 tag 的镜像。"
    exit 1
  fi
}

do_install() {
  ensure_docker_stack

  echo "请选择："
  echo "1) 服务端"
  echo "2) 客户端"
  local ROLE
  prompt ROLE "输入 1 或 2" "1"

  local IMAGE BASE_URL
  prompt IMAGE "请输入镜像地址" "${DEFAULT_IMAGE}"
  prompt BASE_URL "基准配置文件URL（appsettings.base.json raw 链接）" "${DEFAULT_BASE_CFG_URL}"

  download_base_cfg "$BASE_URL"
  cd "$APP_DIR"

  # 清理旧 watchtower（你之前用过，避免遗留）
  docker rm -f watchtower >/dev/null 2>&1 || true

  if [[ "$ROLE" == "1" ]]; then
    local SERVER_PUBLIC_IP
    # 给个“尽力自动检测”的默认值（失败就空）
    local autoip=""
    autoip="$(curl_retry -sS https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$autoip" ]]; then
      prompt SERVER_PUBLIC_IP "请输入您的IP地址（服务端对外 IP）" "$autoip"
    else
      prompt SERVER_PUBLIC_IP "请输入您的IP地址（服务端对外 IP）" ""
    fi

    jq --arg ip "$SERVER_PUBLIC_IP" \
      '.ip.public=$ip | .ip.interface=$ip' \
      appsettings.base.json > appsettings.json

    write_compose_server "$IMAGE"

  elif [[ "$ROLE" == "2" ]]; then
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：当前宿主机不支持 TUN（或未开启），client 模式无法运行"

    local SERVER_IP guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端IP（用于 client.server）" ""

    guid="$(gen_guid)"
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"; netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"; gw="${netinfo#*|}"

    if [[ -z "$lan" ]]; then
      warn "没检测到客户端内网IP（src），请手动输入。"
      prompt lan "请输入客户端内网IP（用于 http-proxy/socks-proxy bind）" ""
    else
      info "检测到客户端内网IP: ${lan}"
    fi

    if [[ -z "$nic" ]]; then
      warn "没检测到默认网卡名（dev），请手动输入。"
      prompt nic "请输入默认网卡名（例如 eth0/ens3/ens192）" ""
    else
      info "检测到默认网卡: ${nic}"
    fi

    if [[ -z "$gw" ]]; then
      warn "没检测到默认网关（via），请手动输入。"
      prompt gw "请输入默认网关（例如 192.168.1.1）" ""
    else
      info "检测到默认网关: ${gw}"
    fi

    jq --arg srv "ppp://${SERVER_IP}:20000/" \
      --arg guid "$guid" \
      --arg lan "$lan" \
      ' .client.server=$srv
        | .client.guid=$guid
        | .client["http-proxy"].bind=$lan
        | .client["socks-proxy"].bind=$lan ' \
      appsettings.base.json > appsettings.json

    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    # 你之前踩过：不要把 sysctl 写到容器里，network_mode: host 会直接报错
    # 正确做法：只改宿主机
    enable_ip_forward_host

    write_compose_client "$IMAGE" "$nic" "$gw"
  else
    die "输入错误，只能是 1 或 2"
  fi

  echo
  info "启动 openppp2..."
  cd "$APP_DIR"
  compose up -d --remove-orphans

  health_check

  setup_systemd_weekly_update

  echo
  echo "完成！"
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f openppp2"
  echo "查看定时器：systemctl list-timers --all | grep openppp2"
  echo "手动触发更新：systemctl start openppp2-update.service"
}

do_uninstall() {
  # 卸载尽量“宽容”：即使 docker 不可用也清理文件与 systemd
  info "停止并移除 systemd 定时更新（如果存在）..."
  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh >/dev/null 2>&1 || true
  if has_systemd; then systemctl daemon-reload >/dev/null 2>&1 || true; fi

  # 清理旧 watchtower（如果曾经用过）
  if need_cmd docker; then
    docker rm -f watchtower >/dev/null 2>&1 || true
  fi

  if [[ -d "$APP_DIR" ]] && need_cmd docker; then
    cd "$APP_DIR"
    detect_compose >/dev/null 2>&1 || true
    if [[ -n "$COMPOSE_KIND" ]]; then
      info "停止并删除容器..."
      compose down --remove-orphans >/dev/null 2>&1 || true
    else
      # 兜底：直接删容器
      docker rm -f openppp2 >/dev/null 2>&1 || true
    fi
  fi

  info "删除目录 ${APP_DIR} ..."
  rm -rf "$APP_DIR"

  # 可选：恢复 ip_forward 持久化配置（如果你不想保留）
  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  echo "卸载完成（Docker 本身未卸载）。"
}

main() {
  is_root || die "请用 root 执行：sudo bash $0"

  echo "请选择："
  echo "1) 安装 openppp2"
  echo "2) 卸载 openppp2"
  local ACTION
  prompt ACTION "输入 1 或 2" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    *) die "输入错误" ;;
  esac
}

main "$@"

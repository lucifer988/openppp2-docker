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

die() { echo "[!]" "$@" >&2; exit 1; }

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
  # avoid noisy interactive prompts
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

ensure_basic_tools() {
  # curl/jq/iproute2 are needed for config editing & IP detection
  apt_install ca-certificates curl jq iproute2 gnupg || true
}

start_docker_daemon() {
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
    systemctl enable --now containerd >/dev/null 2>&1 || true
    systemctl start containerd >/dev/null 2>&1 || true
  else
    service containerd start >/dev/null 2>&1 || true
    service docker start >/dev/null 2>&1 || true
  fi
}

ensure_docker_stack() {
  ensure_basic_tools

  # Step 1: install docker if command missing OR daemon not available
  local docker_ok="no"
  if need_cmd docker && docker info >/dev/null 2>&1; then
    docker_ok="yes"
  fi

  if [[ "$docker_ok" != "yes" ]]; then
    echo "[*] Docker 未就绪（可能未安装或 daemon 未启动），开始安装/修复..."
    # Debian/Ubuntu: prefer distro packages for max compatibility
    # docker-compose-plugin may not exist on some repos; fall back to docker-compose
    apt_install iptables uidmap || true
    apt_install containerd docker.io || true
    # compose plugin sometimes missing; ignore failure and use docker-compose
    apt_install docker-compose-plugin || true
    apt_install docker-compose || true

    start_docker_daemon

    if ! docker info >/dev/null 2>&1; then
      echo "[!] Docker daemon 仍不可用。请把下面两条命令的输出贴出来："
      echo "    systemctl status docker --no-pager -l"
      echo "    journalctl -u docker -n 200 --no-pager"
      echo
      echo "常见原因："
      echo " - 你在 OpenVZ/LXC 这类不支持 Docker 的容器/VPS 里（需要换成 KVM/物理机/支持容器的 VPS）"
      echo " - 内核/权限限制导致 overlay2/iptables 不可用"
      exit 1
    fi
  fi

  # Step 2: choose compose
  if ! detect_compose; then
    # try install docker-compose and detect again
    apt_install docker-compose || true
    detect_compose || die "未检测到 compose（docker compose 或 docker-compose）。请安装后重试。"
  fi

  echo "[*] 使用 compose：${COMPOSE_KIND}"
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

  # fallback
  if [[ -z "$dev" ]]; then dev="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')" || true; fi
  if [[ -z "$gw"  ]]; then gw="$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')" || true; fi

  echo "${lan:-}|${dev:-}|${gw:-}"
}

download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"
  echo "[*] 下载基准配置..."
  curl -fsSL "$url" -o appsettings.base.json
}

enable_ip_forward_host() {
  echo "[*] 开启宿主机 IPv4 转发（client 模式需要）..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
  cat >/etc/sysctl.d/99-openppp2.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

write_compose_server() {
  local image="$1"
  cat >"$COMPOSE_FILE" <<EOF
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
}

write_compose_client() {
  local image="$1" nic="$2" gw="$3"

  cat >"$COMPOSE_FILE" <<EOF
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
}

setup_systemd_weekly_update() {
  echo
  echo "[*] 设置 systemd 每周自动更新（拉最新镜像并重启 openppp2）"
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
"${dc[@]}" up -d openppp2
EOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'EOF'
[Unit]
Description=Update openppp2 container image

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
    echo "[!] 你的环境没有 systemd，无法启用 timer。你可以改用 crontab 定时执行 /usr/local/bin/openppp2-update.sh"
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

  if [[ "$ROLE" == "1" ]]; then
    local SERVER_PUBLIC_IP
    prompt SERVER_PUBLIC_IP "请输入您的IP地址（服务端对外 IP）" ""

    jq --arg ip "$SERVER_PUBLIC_IP" \
      '.ip.public=$ip | .ip.interface=$ip' \
      appsettings.base.json > appsettings.json

    write_compose_server "$IMAGE"

  elif [[ "$ROLE" == "2" ]]; then
    local SERVER_IP guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端IP（用于 client.server）" ""

    guid="$(gen_guid)"
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"; netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"; gw="${netinfo#*|}"

    if [[ -z "$lan" ]]; then
      echo "[!] 没检测到客户端内网IP（src），请手动输入。"
      prompt lan "请输入客户端内网IP（用于 http-proxy/socks-proxy bind）" ""
    else
      echo "[*] 检测到客户端内网IP: ${lan}"
    fi
    if [[ -z "$nic" ]]; then
      echo "[!] 没检测到默认网卡名（dev），请手动输入。"
      prompt nic "请输入默认网卡名（例如 eth0/ens3/ens192）" ""
    else
      echo "[*] 检测到默认网卡: ${nic}"
    fi
    if [[ -z "$gw" ]]; then
      echo "[!] 没检测到默认网关（via），请手动输入。"
      prompt gw "请输入默认网关（例如 192.168.1.1）" ""
    else
      echo "[*] 检测到默认网关: ${gw}"
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

    enable_ip_forward_host
    write_compose_client "$IMAGE" "$nic" "$gw"
  else
    die "输入错误，只能是 1 或 2"
  fi

  echo
  echo "[*] 启动 openppp2..."
  cd "$APP_DIR"
  compose up -d

  setup_systemd_weekly_update

  echo
  echo "完成！"
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f openppp2"
  echo "查看定时器：systemctl list-timers --all | grep openppp2"
  echo "手动触发更新：systemctl start openppp2-update.service"
}

do_uninstall() {
  ensure_docker_stack

  echo "[*] 停止并移除 systemd 定时更新..."
  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh || true
  if has_systemd; then systemctl daemon-reload >/dev/null 2>&1 || true; fi

  # 清理旧 watchtower（如果曾经用过）
  docker rm -f watchtower 2>/dev/null || true

  if [[ -d "$APP_DIR" ]]; then
    cd "$APP_DIR"
    detect_compose || true
    if [[ -n "$COMPOSE_KIND" ]]; then
      echo "[*] 停止并删除容器..."
      compose down --remove-orphans >/dev/null 2>&1 || true
    fi
  fi

  echo "[*] 删除目录 ${APP_DIR} ..."
  rm -rf "$APP_DIR"

  # 可选：恢复 ip_forward 持久化配置（如果你不想保留）
  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  echo "卸载完成（Docker 本身未卸载）。"
}

main() {
  if ! is_root; then
    die "请用 root 执行：sudo bash $0"
  fi

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

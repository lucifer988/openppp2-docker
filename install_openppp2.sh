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

# 通用交互函数：支持同名环境变量覆盖
prompt() {
  local __var="$1" __msg="$2" __def="${3:-}"
  local __val=""

  local __env_val="${!__var-}"
  if [[ -n "$__env_val" ]]; then
    __val="$__env_val"
    printf -v "$__var" "%s" "$__val"
    info "使用环境变量 ${__var}=${__val}"
    return 0
  fi

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
  apt-get update -y
  apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "$@"
}

curl_retry() {
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 --max-time 120 "$@"
}

ensure_basic_tools() {
  if need_cmd apt-get; then
    apt_install ca-certificates curl jq iproute2 gnupg
  fi
  need_cmd curl || die "curl 未安装成功，请检查 apt 源或网络。"
  need_cmd jq || die "jq 未安装成功，请检查 apt 源或网络。"
  need_cmd ip || die "iproute2 未安装成功，请检查 apt 源或网络。"
  need_cmd ss || die "ss 未安装成功，请检查 iproute2 是否正确安装。"
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

  if docker_daemon_ok; then
    info "已检测到可用的 Docker 环境。"
  else
    if ! need_cmd apt-get; then
      die "未检测到 apt-get，且系统未安装可用的 Docker。当前脚本仅支持使用 apt 的 Debian/Ubuntu 系统。"
    fi

    info "检测到未安装或未配置好的 Docker，尝试通过 apt 安装（Debian/Ubuntu 默认仓库）..."
    apt_install containerd docker.io iptables
    start_docker_daemon

    if ! docker_daemon_ok; then
      info "Docker 已安装但 daemon 仍未就绪，尝试再次修复..."
      start_docker_daemon
    fi
  fi

  if ! docker_daemon_ok; then
    warn "Docker daemon 仍不可用，将输出诊断信息："
    if has_systemd; then
      systemctl status docker --no-pager -l || true
      echo "-----"
      journalctl -u docker -n 200 --no-pager || true
    else
      service docker status || true
    fi
    echo
    die "Docker daemon 不可用（常见原因：宿主为 OpenVZ/LXC，不支持 Docker；或内核/权限限制导致 overlay2/iptables 不可用）。"
  fi

  if ! detect_compose; then
    if need_cmd apt-get; then
      info "未检测到 docker compose，尝试安装 docker-compose-plugin..."
      apt_install docker-compose-plugin || die "安装 docker-compose-plugin 失败，请检查 apt 源或网络。"
    fi
  fi

  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"
  else
    if dpkg -s docker-compose-plugin >/dev/null 2>&1; then
      :
    else
      if need_cmd apt-get; then
        info "尝试安装独立的 docker-compose..."
        apt_install docker-compose || die "安装 docker-compose 失败，请检查 apt 源或网络。"
      fi
    fi
    detect_compose || die "仍未检测到 compose（docker compose 或 docker-compose）。请手动安装后再运行本脚本。"
  fi

  info "已选择使用 compose：${COMPOSE_KIND}"
}

gen_guid() {
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

# 检查端口是否被占用（TCP/UDP 任意）
is_port_in_use() {
  local port="$1"
  ss -tuln 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/.*://g' | grep -qx "$port"
}

# 在 10000-60000 区间内找一个未被使用的端口
random_free_port() {
  local p tries=0
  while :; do
    p=$(( RANDOM % 50001 + 10000 ))  # 10000~60000
    if ! is_port_in_use "$p"; then
      echo "$p"
      return 0
    fi
    tries=$((tries+1))
    if [[ "$tries" -gt 200 ]]; then
      die "在 10000-60000 区间内未能找到空闲端口，请检查当前端口占用情况。"
    fi
  done
}

# 返回 "LAN_IP|DEV|GW"
detect_net() {
  local out lan dev gw
  out="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
  lan="$(awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")"
  dev="$(awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")"
  gw="$(awk '/via/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$out")"

  if [[ -z "$dev" ]]; then dev="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')" || true; fi
  if [[ -z "$gw"  ]]; then gw="$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')" || true; fi
  if [[ -z "$lan" ]]; then
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
  info "开始下载基准配置文件 appsettings.base.json ..."
  if ! curl_retry -sS "$url" -o appsettings.base.json; then
    die "下载基准配置失败，请检查 URL 或网络是否正常：$url"
  fi
}

enable_ip_forward_host() {
  info "尝试在宿主机开启 IPv4 转发（client 模式需要）..."
  if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    cat >/etc/sysctl.d/99-openppp2.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null 2>&1 || true
  else
    warn "写入 sysctl 失败（可能权限受限或宿主不支持修改），client 模式可能无法正常转发。"
    warn "你可以手动执行：sysctl -w net.ipv4.ip_forward=1"
  fi
}

compose_header() {
  if [[ "$COMPOSE_KIND" == "docker-compose" ]]; then
    echo 'version: "3.8"'
  fi
}

write_compose_server() {
  local image="$1" cfg="$2"
  {
    compose_header
    cat <<EOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
EOF
  } >"$COMPOSE_FILE"
}

# 生成首个 client 服务（覆盖写 compose）
write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun_host="$6" tun_name="$7" tun_ip="$8" tun_gw="$9"

  {
    compose_header
    cat <<EOF
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
    volumes:
      - ./${cfg}:/opt/openppp2/${cfg}:ro
      - ./ip.txt:/opt/openppp2/ip.txt:ro
      - ./dns-rules.txt:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=${cfg}"
EOF

    if [[ "$tun_host" == "yes" ]]; then
      echo '      - "--tun-host"'
    fi

    cat <<EOF
      - "--tun=${tun_name}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
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

# 追加一个新的 client 服务（用于“新增 openppp2 客户端实例”）
append_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" ipfile="$6" dnsfile="$7" tun_host="$8" tun_name="$9" tun_ip="${10}" tun_gw="${11}"

  {
    cat <<EOF

  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
    volumes:
      - ./${cfg}:/opt/openppp2/${cfg}:ro
      - ./${ipfile}:/opt/openppp2/ip.txt:ro
      - ./${dnsfile}:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=${cfg}"
EOF

    if [[ "$tun_host" == "yes" ]]; then
      echo '      - "--tun-host"'
    fi

    cat <<EOF
      - "--tun=${tun_name}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
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
  } >>"$COMPOSE_FILE"
}

setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "未检测到 systemd，无法配置 systemd 定时更新。你可以使用 crontab 定时执行 /usr/local/bin/openppp2-update.sh。"
    return 0
  fi

  echo
  info "配置 systemd 每周自动更新（拉取最新镜像并重启 openppp2 容器）"
  echo "说明：OnCalendar 示例："
  echo "  Sun *-*-* 03:00:00  -> 每周日 03:00 执行"
  echo "  Mon *-*-* 04:30:00  -> 每周一 04:30 执行"
  local oncal
  prompt oncal "请输入定时任务的 OnCalendar 表达式" "${DEFAULT_ONCAL}"

  cat >/usr/local/bin/openppp2-update.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

"${dc[@]}" pull
"${dc[@]}" up -d --remove-orphans
EOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'EOF'
[Unit]
Description=Update openppp2 container images
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

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer

  info "已启用 systemd 定时更新：openppp2-update.timer"
}

health_check() {
  local role=""
  if [[ -f "${APP_DIR}/.role" ]]; then
    role="$(cat "${APP_DIR}/.role" 2>/dev/null || echo "")"
  fi

  local svc="openppp2"
  if [[ "$role" == "client" ]]; then
    if [[ -f "${APP_DIR}/.client_main_service" ]]; then
      svc="$(cat "${APP_DIR}/.client_main_service" 2>/dev/null || echo "openppp2")"
    fi
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx "$svc"; then
    if [[ "$role" == "client" ]]; then
      warn "openppp2 主客户端容器未处于运行状态（预期容器名：${svc}）。请检查日志："
    else
      warn "openppp2 容器未处于运行状态。请检查日志："
    fi
    echo "  cd ${APP_DIR} && ${COMPOSE_KIND} logs --tail=200 ${svc}"
    echo
    warn "如果看到 “io_uring_queue_init: Operation not permitted” 之类错误："
    warn "  - 说明镜像为 io-uring 版本，在某些内核/安全策略下会被限制。"
    warn "  - 请换用 non-io-uring 的 openppp2 镜像或其它 tag。"
    exit 1
  fi
}

do_install() {
  ensure_docker_stack

  echo "=============================="
  echo "  请选择安装/部署角色："
  echo "    1) 服务端（Server）"
  echo "    2) 客户端（Client）"
  echo "=============================="
  local ROLE
  prompt ROLE "请输入数字选择（1 或 2）" "1"

  local IMAGE BASE_URL
  prompt IMAGE "请输入镜像地址" "${DEFAULT_IMAGE}"
  prompt BASE_URL "请输入基准配置文件 URL（appsettings.base.json 的 raw 链接）" "${DEFAULT_BASE_CFG_URL}"

  download_base_cfg "$BASE_URL"
  cd "$APP_DIR"

  docker rm -f watchtower >/dev/null 2>&1 || true

  if [[ "$ROLE" == "1" ]]; then
    # 服务端
    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的服务端配置文件名称（例如 appsettings.json 或 appsettings-server.json）" "appsettings.json"

    local SERVER_PUBLIC_IP
    local autoip=""
    autoip="$(curl_retry -sS https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$autoip" ]]; then
      prompt SERVER_PUBLIC_IP "请输入服务端对外 IP 地址（用于配置 ip.public / ip.interface）" "$autoip"
    else
      prompt SERVER_PUBLIC_IP "请输入服务端对外 IP 地址（用于配置 ip.public / ip.interface）" ""
    fi

    jq --arg ip "$SERVER_PUBLIC_IP" \
      '.ip.public=$ip | .ip.interface=$ip' \
      appsettings.base.json > "$APP_CFG_NAME"

    write_compose_server "$IMAGE" "$APP_CFG_NAME"

    echo "server" > "${APP_DIR}/.role"

  elif [[ "$ROLE" == "2" ]]; then
    # 客户端
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：当前宿主机不支持 TUN（或未开启），client 模式无法运行。"

    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的客户端配置文件名称（例如 appsettings.json 或 appsettings-HK.json）" "appsettings.json"

    local MAIN_SERVICE_NAME
    prompt MAIN_SERVICE_NAME "请输入主客户端实例名称（容器/服务名）" "openppp2"

    local SERVER_IP SERVER_PORT guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端 IP（用于 client.server，例如 1.2.3.4）" ""
    prompt SERVER_PORT "请输入服务端端口（用于 client.server，例如 20000）" "20000"

    guid="$(gen_guid)"
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"; netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"; gw="${netinfo#*|}"

    if [[ -z "${lan:-}" ]]; then
      warn "未能自动检测到客户端内网 IP（src），请手动输入。"
      prompt lan "请输入客户端内网 IP（用于 http-proxy/socks-proxy bind，例如 192.168.1.100）" ""
    else
      info "检测到客户端内网 IP：${lan}"
    fi

    if [[ -z "${nic:-}" ]]; then
      warn "未能自动检测到默认网卡名（dev），请手动输入。"
      prompt nic "请输入默认网卡名（例如 eth0、ens3、ens192）" ""
    else
      info "检测到默认网卡：${nic}"
    fi

    if [[ -z "${gw:-}" ]]; then
      warn "未能自动检测到默认网关（via），请手动输入。"
      prompt gw "请输入默认网关（例如 192.168.1.1）" ""
    else
      info "检测到默认网关：${gw}"
    fi

    local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

    local MAIN_TUN_HOST_CHOICE MAIN_TUN_HOST_FLAG
    prompt MAIN_TUN_HOST_CHOICE "是否将该客户端设置为默认出网（全局代理）？(y/n)" "y"
    if [[ "$MAIN_TUN_HOST_CHOICE" =~ ^[Yy]$ ]]; then
      MAIN_TUN_HOST_FLAG="yes"
    else
      MAIN_TUN_HOST_FLAG="no"
    fi

    # 为 HTTP/SOCKS 随机分配端口
    local HTTP_PORT SOCKS_PORT
    HTTP_PORT="$(random_free_port)"
    SOCKS_PORT="$(random_free_port)"
    while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do
      SOCKS_PORT="$(random_free_port)"
    done

    jq --arg srv "$SERVER_URI" \
      --arg guid "$guid" \
      --arg lan "$lan" \
      --argjson hport "$HTTP_PORT" \
      --argjson sport "$SOCKS_PORT" \
      ' .client.server=$srv
        | .client.guid=$guid
        | .client["http-proxy"].bind=$lan
        | .client["socks-proxy"].bind=$lan
        | .client["http-proxy"].port=$hport
        | .client["socks-proxy"].port=$sport ' \
      appsettings.base.json > "$APP_CFG_NAME"

    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    enable_ip_forward_host

    local main_tun_name="ppp0"
    local tun_ip="10.0.0.2"
    local tun_gw="10.0.0.1"

    write_compose_client "$IMAGE" "$nic" "$gw" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME" "$MAIN_TUN_HOST_FLAG" "$main_tun_name" "$tun_ip" "$tun_gw"

    echo "client" > "${APP_DIR}/.role"
    echo "$MAIN_SERVICE_NAME" > "${APP_DIR}/.client_main_service"

    echo
    echo "当前客户端配置信息："
    echo "  配置文件：${APP_CFG_NAME}"
    echo "  server   ：${SERVER_URI}"
    echo "  SOCKS5   ：${lan}:${SOCKS_PORT}"
    echo "  HTTP     ：${lan}:${HTTP_PORT}"
  else
    die "角色选择错误，只能输入 1 或 2。"
  fi

  echo
  info "开始启动 openppp2 容器..."
  cd "$APP_DIR"
  compose up -d --remove-orphans

  health_check
  setup_systemd_weekly_update

  echo
  echo "===== 安装完成 ====="
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f <服务名>"
  echo "查看定时器（若使用 systemd）：systemctl list-timers --all | grep openppp2"
  echo "手动触发更新（若使用 systemd）：systemctl start openppp2-update.service"
}

do_uninstall() {
  info "开始卸载 openppp2（不卸载 Docker 本身）..."

  info "停止并移除可能存在的 systemd 定时更新..."
  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh >/dev/null 2>&1 || true
  if has_systemd; then systemctl daemon-reload >/dev/null 2>&1 || true; fi

  if need_cmd docker; then
    docker rm -f watchtower >/dev/null 2>&1 || true
  fi

  if [[ -d "$APP_DIR" ]] && need_cmd docker; then
    cd "$APP_DIR"
    detect_compose >/dev/null 2>&1 || true
    if [[ -n "$COMPOSE_KIND" ]]; then
      info "停止并删除 openppp2 相关容器..."
      compose down --remove-orphans >/dev/null 2>&1 || true
    else
      docker rm -f openppp2 >/dev/null 2>&1 || true
    fi
  fi

  info "删除目录 ${APP_DIR} ..."
  rm -rf "$APP_DIR"

  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  echo "卸载完成（Docker 本身未卸载）。"
}

# 新增 openppp2 客户端实例（多隧道）
do_add_client() {
  ensure_docker_stack

  if [[ ! -d "$APP_DIR" ]] || [[ ! -f "$COMPOSE_FILE" ]]; then
    die "未检测到已有的 openppp2 安装，请先使用 1) 安装 openppp2（client）后再使用本功能。"
  fi

  local role="unknown"
  if [[ -f "${APP_DIR}/.role" ]]; then
    role="$(cat "${APP_DIR}/.role" 2>/dev/null || echo unknown)"
  fi

  if [[ "$role" != "client" ]]; then
    die "当前安装角色不是客户端（可能是服务端），根据要求禁止使用 3) 新增 openppp2。"
  fi

  cd "$APP_DIR"

  if [[ ! -f appsettings.base.json ]]; then
    local BASE_URL
    prompt BASE_URL "未找到 appsettings.base.json，请输入基准配置文件 URL（appsettings.base.json 的 raw 链接）" "${DEFAULT_BASE_CFG_URL}"
    download_base_cfg "$BASE_URL"
  fi

  local IMAGE
  IMAGE="$(awk '/image:/ {print $2; exit}' "$COMPOSE_FILE" 2>/dev/null || true)"
  if [[ -z "$IMAGE" ]]; then
    prompt IMAGE "未能从 docker-compose.yml 中解析出镜像地址，请输入镜像地址" "${DEFAULT_IMAGE}"
  fi

  local SERVER_IP SERVER_PORT guid lan nic gw netinfo
  prompt SERVER_IP "请输入新增客户端要连接的服务端 IP（例如 1.2.3.4）" ""
  prompt SERVER_PORT "请输入新增客户端要连接的服务端端口（例如 20000）" "20000"

  guid="$(gen_guid)"
  netinfo="$(detect_net)"
  lan="${netinfo%%|*}"; netinfo="${netinfo#*|}"
  nic="${netinfo%%|*}"; gw="${netinfo#*|}"

  if [[ -z "${lan:-}" ]]; then
    warn "未能自动检测到客户端内网 IP（src），请手动输入。"
    prompt lan "请输入客户端内网 IP（用于 http-proxy/socks-proxy bind，例如 192.168.1.100）" ""
  else
    info "检测到客户端内网 IP：${lan}"
  fi

  if [[ -z "${nic:-}" ]]; then
    warn "未能自动检测到默认网卡名（dev），请手动输入。"
    prompt nic "请输入默认网卡名（例如 eth0、ens3、ens192）" ""
  else
    info "检测到默认网卡：${nic}"
  fi

  if [[ -z "${gw:-}" ]]; then
    warn "未能自动检测到默认网关（via），请手动输入。"
    prompt gw "请输入默认网关（例如 192.168.1.1）" ""
  else
    info "检测到默认网关：${gw}"
  fi

  local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

  local idx=2
  while grep -q "openppp2-${idx}:" "$COMPOSE_FILE" 2>/dev/null; do
    idx=$((idx+1))
  done
  local default_svc="openppp2-${idx}"

  local SVC_NAME
  prompt SVC_NAME "请输入新客户端实例名称（容器/服务名）" "$default_svc"

  if grep -qE "^[[:space:]]${SVC_NAME}:" "$COMPOSE_FILE" 2>/dev/null; then
    die "服务名 ${SVC_NAME} 已在 docker-compose.yml 中存在，请换一个名称后重试。"
  fi

  local cfg_default="appsettings-${SVC_NAME}.json"
  local CFG_NAME
  prompt CFG_NAME "请输入该客户端配置文件名称" "$cfg_default"

  local ipfile="ip-${SVC_NAME}.txt"
  local dnsfile="dns-rules-${SVC_NAME}.txt"

  local TUN_HOST_CHOICE TUN_HOST_FLAG
  prompt TUN_HOST_CHOICE "是否将该客户端设置为默认出网（全局代理）？(y/n)" "n"
  if [[ "$TUN_HOST_CHOICE" =~ ^[Yy]$ ]]; then
    TUN_HOST_FLAG="yes"
  else
    TUN_HOST_FLAG="no"
  fi

  local tun_idx="$idx"
  local tun_ip="10.0.${tun_idx}.2"
  local tun_gw="10.0.${tun_idx}.1"
  local tun_name="ppp${tun_idx}"

  # 为 HTTP/SOCKS 随机分配端口
  local HTTP_PORT SOCKS_PORT
  HTTP_PORT="$(random_free_port)"
  SOCKS_PORT="$(random_free_port)"
  while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do
    SOCKS_PORT="$(random_free_port)"
  done

  jq --arg srv "$SERVER_URI" \
    --arg guid "$guid" \
    --arg lan "$lan" \
    --argjson hport "$HTTP_PORT" \
    --argjson sport "$SOCKS_PORT" \
    ' .client.server=$srv
      | .client.guid=$guid
      | .client["http-proxy"].bind=$lan
      | .client["socks-proxy"].bind=$lan
      | .client["http-proxy"].port=$hport
      | .client["socks-proxy"].port=$sport ' \
    appsettings.base.json > "${CFG_NAME}"

  [[ -f "$ipfile" ]] || : > "$ipfile"
  [[ -f "$dnsfile" ]] || : > "$dnsfile"

  enable_ip_forward_host

  append_compose_client "${IMAGE}" "${nic}" "${gw}" "${SVC_NAME}" "${CFG_NAME}" "${ipfile}" "${dnsfile}" "${TUN_HOST_FLAG}" "${tun_name}" "${tun_ip}" "${tun_gw}"

  info "启动新增客户端实例：${SVC_NAME} ..."
  compose up -d --remove-orphans "${SVC_NAME}"

  echo
  echo "当前新增客户端配置信息："
  echo "  配置文件：${CFG_NAME}"
  echo "  server   ：${SERVER_URI}"
  echo "  SOCKS5   ：${lan}:${SOCKS_PORT}"
  echo "  HTTP     ：${lan}:${HTTP_PORT}"
  echo
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f ${SVC_NAME}"
}

# 查看所有客户端配置文件的信息（server + SOCKS/HTTP）
do_show_info() {
  if [[ ! -d "$APP_DIR" ]]; then
    die "未检测到 ${APP_DIR} 目录，似乎尚未安装 openppp2。"
  fi

  cd "$APP_DIR"

  local found=0
  for f in appsettings*.json; do
    [[ -f "$f" ]] || continue
    # 跳过基准配置
    [[ "$f" == "appsettings.base.json" ]] && continue

    local server socks_bind socks_port http_bind http_port
    server="$(jq -r '(.client.server // empty)' "$f")"

    if [[ -z "$server" ]]; then
      continue
    fi

    socks_bind="$(jq -r '(.client["socks-proxy"].bind // "")' "$f")"
    socks_port="$(jq -r '(.client["socks-proxy"].port // "")' "$f")"
    http_bind="$(jq -r '(.client["http-proxy"].bind // "")' "$f")"
    http_port="$(jq -r '(.client["http-proxy"].port // "")' "$f")"

    found=1
    echo "----------------------------------------"
    echo "配置文件：$f"
    echo "  client.server ：$server"
    if [[ -n "$socks_bind" || -n "$socks_port" ]]; then
      echo "  SOCKS5        ：${socks_bind}:${socks_port}"
    else
      echo "  SOCKS5        ：未配置"
    fi
    if [[ -n "$http_bind" || -n "$http_port" ]]; then
      echo "  HTTP          ：${http_bind}:${http_port}"
    else
      echo "  HTTP          ：未配置"
    fi
  done

  if [[ "$found" -eq 0 ]]; then
    echo "未在 ${APP_DIR} 中找到包含 client.server 的客户端配置文件。"
  else
    echo "----------------------------------------"
    echo "以上为当前所有客户端配置的 server / SOCKS5 / HTTP 信息。"
  fi
}

check_env_supported() {
  is_root || die "请使用 root 身份执行本脚本，例如：sudo bash $0"

  if ! need_cmd apt-get; then
    warn "未检测到 apt-get，本脚本当前仅支持 Debian/Ubuntu 系列。"
    die "请在 Debian/Ubuntu 系统中运行，或自行改造脚本以支持其它发行版。"
  fi

  if [[ ! -f /etc/debian_version ]]; then
    warn "未检测到 /etc/debian_version，系统可能不是标准 Debian/Ubuntu。"
    warn "继续运行可能会失败或产生不可预期行为。"
  fi
}

main() {
  check_env_supported

  echo "=============================="
  echo "  openppp2 一键部署脚本"
  echo "=============================="
  echo "请选择操作："
  echo "  1) 安装 openppp2"
  echo "  2) 卸载 openppp2"
  echo "  3) 新增 openppp2 客户端实例"
  echo "  4) 查看客户端配置和代理信息"
  echo "=============================="

  local ACTION
  prompt ACTION "请输入数字选择（1 / 2 / 3 / 4）" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_add_client ;;
    4) do_show_info ;;
    *) die "输入错误，只能是 1 / 2 / 3 / 4。" ;;
  esac
}

main "$@"

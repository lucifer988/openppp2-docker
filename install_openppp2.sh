#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"

BASE_CFG_URL_DEFAULT="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"
IMAGE_DEFAULT="ghcr.io/lucifer988/openppp2:latest"

UPDATE_SCRIPT="/usr/local/bin/openppp2-update.sh"
SERVICE_FILE="/etc/systemd/system/openppp2-update.service"
TIMER_FILE="/etc/systemd/system/openppp2-update.timer"

# 默认：每周日 03:00（按本机时区）
ONCAL_DEFAULT="Sun *-*-* 03:00:00"

log() { echo -e "$*"; }
die() { echo -e "[!] $*" >&2; exit 1; }

as_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请用 root 执行：sudo bash $0"
  fi
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

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

detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_CODENAME="${VERSION_CODENAME:-}"
  else
    OS_ID=""
    OS_CODENAME=""
  fi
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi
  if need_cmd docker-compose; then
    echo "docker-compose"
    return 0
  fi
  return 1
}

start_docker_daemon() {
  if need_cmd systemctl; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service docker start >/dev/null 2>&1 || true
  fi
}

apt_install() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

install_docker_official_repo_deb() {
  apt_install ca-certificates curl gnupg

  install -m 0755 -d /etc/apt/keyrings

  # 避免覆盖交互：先删掉旧文件，再 batch/yes 强制写入
  rm -f /etc/apt/keyrings/docker.gpg
  tmpkey="$(mktemp)"
  if ! curl -fsSL --retry 8 --retry-delay 2 --retry-all-errors \
      "https://download.docker.com/linux/${OS_ID}/gpg" -o "$tmpkey"; then
    rm -f "$tmpkey"
    return 1
  fi
  if ! gpg --dearmor --batch --yes -o /etc/apt/keyrings/docker.gpg "$tmpkey"; then
    rm -f "$tmpkey"
    return 1
  fi
  rm -f "$tmpkey"
  chmod a+r /etc/apt/keyrings/docker.gpg

  [[ -n "${OS_CODENAME}" ]] || return 1

  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} ${OS_CODENAME} stable
EOF

  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_docker_distro_repo() {
  # Debian/Ubuntu 自带仓库
  apt_install docker.io docker-compose
}

ensure_docker_installed() {
  if need_cmd docker; then
    return 0
  fi

  detect_os
  log "[*] 未检测到 docker，开始安装..."

  if [[ "${OS_ID}" == "debian" || "${OS_ID}" == "ubuntu" ]]; then
    if install_docker_official_repo_deb; then
      log "[*] 已通过 Docker 官方仓库安装完成"
    else
      log "[!] Docker 官方仓库安装失败（常见原因：download.docker.com 被 reset/阻断），改用系统自带 docker.io..."
      install_docker_distro_repo
      log "[*] 已通过系统仓库安装完成（docker.io + docker-compose）"
    fi
  else
    die "不支持的系统：${OS_ID:-unknown}（仅内置适配 Debian/Ubuntu）"
  fi
}

ensure_docker_daemon_ready() {
  start_docker_daemon
  if ! docker info >/dev/null 2>&1; then
    die "Docker daemon 不可用。请检查：systemctl status docker"
  fi
}

ensure_compose_ready() {
  if compose_cmd >/dev/null 2>&1; then
    return 0
  fi

  log "[*] 未检测到 compose，安装 docker-compose..."
  apt_install docker-compose

  if ! compose_cmd >/dev/null 2>&1; then
    die "仍未检测到 docker compose / docker-compose，请手动检查安装情况"
  fi
}

ensure_docker_stack() {
  ensure_docker_installed
  ensure_docker_daemon_ready
  ensure_compose_ready
  COMPOSE="$(compose_cmd)"
  log "[*] 使用 compose：${COMPOSE}"
}

gen_guid() {
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

detect_lan_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

# ✅ 关键修复：client 模式在宿主机开启 ip_forward，不在容器里 sysctls（host 网络下会报错）
ensure_host_ip_forward() {
  log "[*] 开启宿主机 IPv4 转发（client 模式需要）..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  cat > /etc/sysctl.d/99-openppp2.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

write_compose_server() {
  local image="$1"
  cat > "$COMPOSE_FILE" <<YAML
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
    volumes:
      - ./appsettings.json:/opt/openppp2/appsettings.json:ro
    security_opt:
      - seccomp=unconfined
YAML
}

write_compose_client() {
  local image="$1"
  cat > "$COMPOSE_FILE" <<YAML
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./appsettings.json:/opt/openppp2/appsettings.json:ro
      - ./ip.txt:/opt/openppp2/ip.txt:ro
      - ./dns-rules.txt:/opt/openppp2/dns-rules.txt:ro
    security_opt:
      - seccomp=unconfined
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
      - "--bypass-iplist-nic=ens192"
      - "--bypass-iplist-ngw=192.168.88.1"
YAML
}

install_systemd_timer_weekly() {
  local oncal="$1"

  cat > "$UPDATE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "[!] compose not found" >&2
  exit 1
fi

${COMPOSE} pull openppp2
${COMPOSE} up -d openppp2
EOF
  chmod +x "$UPDATE_SCRIPT"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Update openppp2 container image

[Service]
Type=oneshot
ExecStart=${UPDATE_SCRIPT}
EOF

  cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${oncal}
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer >/dev/null 2>&1 || true
}

remove_systemd_timer() {
  systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
  rm -f "$TIMER_FILE" "$SERVICE_FILE" "$UPDATE_SCRIPT"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

do_install() {
  ensure_docker_stack
  apt_install jq curl iproute2 >/dev/null 2>&1 || true

  mkdir -p "$APP_DIR"
  cd "$APP_DIR"

  log ""
  log "请选择："
  log "1) 服务端"
  log "2) 客户端"
  prompt ROLE "输入 1 或 2" "1"

  prompt IMAGE "请输入镜像地址" "$IMAGE_DEFAULT"
  prompt BASE_CFG_URL "基准配置文件URL（appsettings.base.json raw 链接）" "$BASE_CFG_URL_DEFAULT"

  log "[*] 下载基准配置..."
  curl -fsSL "$BASE_CFG_URL" -o appsettings.base.json

  if [[ "$ROLE" == "1" ]]; then
    prompt IPADDR "请输入您的IP地址（服务端对外 IP）" ""
    jq --arg ip "$IPADDR" '.ip.public=$ip | .ip.interface=$ip' appsettings.base.json > appsettings.json
    write_compose_server "$IMAGE"

  elif [[ "$ROLE" == "2" ]]; then
    prompt SERVER_IP "请输入服务端IP（用于 client.server）" ""
    guid="$(gen_guid)"

    lan_ip="$(detect_lan_ip || true)"
    if [[ -z "${lan_ip}" ]]; then
      log "[!] 没检测到内网IP，请手动输入。"
      prompt lan_ip "请输入客户端内网IP（用于 http-proxy/socks-proxy bind）" ""
    else
      log "[*] 检测到客户端内网IP: ${lan_ip}"
    fi

    jq --arg srv "ppp://${SERVER_IP}:20000/" \
       --arg guid "$guid" \
       --arg lan "$lan_ip" \
      '.client.server=$srv
       | .client.guid=$guid
       | .client["http-proxy"].bind=$lan
       | .client["socks-proxy"].bind=$lan' \
      appsettings.base.json > appsettings.json

    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    ensure_host_ip_forward
    write_compose_client "$IMAGE"
  else
    die "输入错误，只能是 1 或 2"
  fi

  log ""
  log "[*] 启动 openppp2..."
  ${COMPOSE} up -d

  log ""
  log "[*] 设置 systemd 每周自动更新（拉最新镜像并重启 openppp2）"
  prompt ONCAL "请输入 OnCalendar（按周）表达式" "$ONCAL_DEFAULT"
  install_systemd_timer_weekly "$ONCAL"

  log ""
  log "完成！"
  log "配置目录：$APP_DIR"
  log "查看日志：cd $APP_DIR && ${COMPOSE} logs -f openppp2"
  log "查看定时器：systemctl list-timers --all | grep openppp2"
  log "手动触发更新：systemctl start openppp2-update.service"
}

do_uninstall() {
  remove_systemd_timer

  if [[ -d "$APP_DIR" ]]; then
    cd "$APP_DIR" || true
    if need_cmd docker && compose_cmd >/dev/null 2>&1; then
      COMPOSE="$(compose_cmd)"
      ${COMPOSE} down --remove-orphans >/dev/null 2>&1 || true
    fi
  fi

  rm -rf "$APP_DIR"
  log "卸载完成（Docker 本身未卸载）。"
}

main() {
  as_root

  log "请选择："
  log "1) 安装 openppp2"
  log "2) 卸载 openppp2"
  prompt ACTION "输入 1 或 2" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    *) die "输入错误" ;;
  esac
}

main "$@"

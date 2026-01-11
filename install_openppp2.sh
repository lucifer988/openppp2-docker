#!/usr/bin/env bash
set -euo pipefail

# =========================
# Config
# =========================
APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"

# 你的仓库里 base 配置的 raw 地址（建议你仓库里就放 appsettings.base.json）
BASE_CFG_URL_DEFAULT="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"

# 你的 GHCR 镜像（latest）
IMAGE_DEFAULT="ghcr.io/lucifer988/openppp2:latest"

# systemd 定时更新（每周一次：周日 03:00，本机时区）
UPDATE_SCRIPT="/usr/local/bin/openppp2-update.sh"
SERVICE_FILE="/etc/systemd/system/openppp2-update.service"
TIMER_FILE="/etc/systemd/system/openppp2-update.timer"

# =========================
# Utils
# =========================
need_cmd() { command -v "$1" >/dev/null 2>&1; }

as_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "[!] 请用 root 执行：sudo bash $0"
    exit 1
  fi
}

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

detect_pkg_manager() {
  if need_cmd apt-get; then echo "apt"; return 0; fi
  echo ""
  return 1
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
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

# =========================
# Docker auto-install
# =========================
install_docker_official_repo_debian() {
  # Docker 官方源（可能在部分网络环境被 reset，因此这里加重试，失败允许降级）
  apt_install ca-certificates curl gnupg

  install -m 0755 -d /etc/apt/keyrings

  if ! curl -fsSL --retry 8 --retry-delay 2 --retry-all-errors \
      https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
    return 1
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg

  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_docker_official_repo_ubuntu() {
  apt_install ca-certificates curl gnupg

  install -m 0755 -d /etc/apt/keyrings

  if ! curl -fsSL --retry 8 --retry-delay 2 --retry-all-errors \
      https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
    return 1
  fi
  chmod a+r /etc/apt/keyrings/docker.gpg

  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_docker_distro_repo() {
  # Debian/Ubuntu 发行版仓库兜底：docker.io + docker-compose(v1)
  apt_install docker.io docker-compose
}

ensure_docker_installed() {
  if need_cmd docker; then
    return 0
  fi

  echo "[*] 未检测到 docker，开始安装..."
  if [[ "$(detect_pkg_manager)" != "apt" ]]; then
    echo "[!] 当前系统没有 apt-get，脚本只实现了 Debian/Ubuntu 自动安装。"
    echo "    请手动安装 Docker 后再运行本脚本。"
    exit 1
  fi

  # 先补齐基础工具（jq 下面也会用）
  apt_install curl jq iproute2

  # 判断发行版
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
  else
    ID=""
  fi

  # 优先官方源（失败则降级发行版仓库）
  if [[ "${ID:-}" == "debian" ]]; then
    if install_docker_official_repo_debian; then
      echo "[*] Docker 官方源安装完成（Debian）"
    else
      echo "[!] Docker 官方源安装失败（常见原因：download.docker.com 被 reset），改用 docker.io 兜底..."
      install_docker_distro_repo
      echo "[*] docker.io 安装完成（Debian 兜底）"
    fi
  elif [[ "${ID:-}" == "ubuntu" ]]; then
    if install_docker_official_repo_ubuntu; then
      echo "[*] Docker 官方源安装完成（Ubuntu）"
    else
      echo "[!] Docker 官方源安装失败，改用 docker.io 兜底..."
      install_docker_distro_repo
      echo "[*] docker.io 安装完成（Ubuntu 兜底）"
    fi
  else
    echo "[!] 未识别发行版（ID=${ID:-unknown}），改用 docker.io 兜底..."
    install_docker_distro_repo
    echo "[*] docker.io 安装完成（兜底）"
  fi
}

ensure_compose_available() {
  if compose_cmd >/dev/null 2>&1; then
    return 0
  fi

  echo "[*] 未检测到 compose，尝试安装 docker-compose..."
  if [[ "$(detect_pkg_manager)" == "apt" ]]; then
    apt_install docker-compose
  fi

  if ! compose_cmd >/dev/null 2>&1; then
    echo "[!] 仍然找不到 compose：请手动安装 docker-compose 或 docker compose 插件。"
    exit 1
  fi
}

ensure_docker_stack() {
  # 1) docker 命令
  ensure_docker_installed

  # 2) daemon 启动 + 检测
  start_docker_daemon
  if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker daemon 不可用，请先检查：systemctl status docker"
    exit 1
  fi

  # 3) compose
  ensure_compose_available

  COMPOSE="$(compose_cmd)"
  echo "[*] 使用 compose：${COMPOSE}"
}

# =========================
# JSON edits & IP helpers
# =========================
gen_guid() {
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

detect_lan_ip() {
  # 取默认路由出口地址（适用于大多数 VPS）
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  echo "${ip:-}"
}

# =========================
# Compose templates
# =========================
write_compose_server() {
  local image="$1"
  mkdir -p "$APP_DIR"
  cat > "$COMPOSE_FILE" <<YAML
version: "3.8"
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
    # io_uring 版本在容器里常见需要放开 seccomp，否则会报 Operation not permitted
    security_opt:
      - seccomp=unconfined
YAML
}

write_compose_client() {
  local image="$1"
  mkdir -p "$APP_DIR"
  cat > "$COMPOSE_FILE" <<YAML
version: "3.8"
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
    sysctls:
      - net.ipv4.ip_forward=1
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

# =========================
# systemd weekly updater
# =========================
install_systemd_timer_weekly() {
  # update 脚本里也做一次 compose 命令自适配，避免环境变化
  cat > "$UPDATE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "[openppp2-update] compose not found"
  exit 1
fi

$COMPOSE pull openppp2
$COMPOSE up -d openppp2
EOF
  chmod +x "$UPDATE_SCRIPT"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Update openppp2 container image

[Service]
Type=oneshot
ExecStart=${UPDATE_SCRIPT}
EOF

  # 每周一次：周日 03:00（按本机时区）；Persistent=true 表示错过会在开机后补跑一次
  cat > "$TIMER_FILE" <<'EOF'
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer
}

remove_systemd_timer() {
  systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
  rm -f "$TIMER_FILE" "$SERVICE_FILE" "$UPDATE_SCRIPT"
  systemctl daemon-reload
}

# =========================
# Install / Uninstall
# =========================
do_install() {
  ensure_docker_stack

  mkdir -p "$APP_DIR"
  cd "$APP_DIR"

  echo
  echo "请选择："
  echo "1) 服务端"
  echo "2) 客户端"
  prompt ROLE "输入 1 或 2" "1"

  prompt IMAGE "请输入镜像地址" "$IMAGE_DEFAULT"
  prompt BASE_CFG_URL "基准配置文件URL（appsettings.base.json raw 链接）" "$BASE_CFG_URL_DEFAULT"

  echo "[*] 下载基准配置..."
  curl -fsSL --retry 5 --retry-delay 2 --retry-all-errors "$BASE_CFG_URL" -o appsettings.base.json

  if [[ "$ROLE" == "1" ]]; then
    prompt IPADDR "请输入您的IP地址（服务端对外 IP）" ""
    # 按你要求：public/interface 都写输入的 IP
    jq --arg ip "$IPADDR" '.ip.public=$ip | .ip.interface=$ip' appsettings.base.json > appsettings.json
    write_compose_server "$IMAGE"

  elif [[ "$ROLE" == "2" ]]; then
    prompt SERVER_IP "请输入服务端IP（用于 client.server）" ""
    local_guid="$(gen_guid)"

    lan_ip="$(detect_lan_ip)"
    if [[ -z "$lan_ip" ]]; then
      echo "[!] 未检测到客户端内网IP，请手动输入。"
      prompt lan_ip "请输入客户端内网IP（用于 http-proxy/socks-proxy bind）" ""
    else
      echo "[*] 检测到客户端内网IP: ${lan_ip}"
    fi

    jq --arg srv "ppp://${SERVER_IP}:20000/" \
       --arg guid "$local_guid" \
       --arg lan "$lan_ip" \
      '.client.server=$srv
       | .client.guid=$guid
       | .client["http-proxy"].bind=$lan
       | .client["socks-proxy"].bind=$lan' \
      appsettings.base.json > appsettings.json

    # 供命令行参数引用（你也可以后续把这两文件做成更完善的模板）
    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    write_compose_client "$IMAGE"
  else
    echo "[!] 输入错误，只能是 1 或 2"
    exit 1
  fi

  echo
  echo "[*] 启动 openppp2..."
  ${COMPOSE} up -d

  echo "[*] 配置 systemd 每周自动更新（替代 watchtower）..."
  install_systemd_timer_weekly

  echo
  echo "完成！"
  echo "配置目录：$APP_DIR"
  echo "查看日志：cd $APP_DIR && ${COMPOSE} logs -f openppp2"
  echo "查看端口：ss -lntup | grep 20000"
  echo "查看定时器：systemctl list-timers --all | grep openppp2"
}

do_uninstall() {
  ensure_docker_stack

  echo "[*] 移除 systemd 定时器..."
  remove_systemd_timer

  if [[ -d "$APP_DIR" ]]; then
    cd "$APP_DIR"
    echo "[*] 停止并删除容器..."
    ${COMPOSE} down --remove-orphans || true
  fi

  echo "[*] 删除目录 $APP_DIR ..."
  rm -rf "$APP_DIR"
  echo "卸载完成（Docker 本身不卸载）。"
}

main() {
  as_root

  echo "请选择："
  echo "1) 安装 openppp2"
  echo "2) 卸载 openppp2"
  prompt ACTION "输入 1 或 2" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    *) echo "[!] 输入错误"; exit 1 ;;
  esac
}

main "$@"

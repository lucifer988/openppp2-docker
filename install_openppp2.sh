#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"

IMAGE_DEFAULT="ghcr.io/lucifer988/openppp2:latest"
BASE_CFG_URL_DEFAULT="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"

COMPOSE=""

need_cmd() { command -v "$1" >/dev/null 2>&1; }

as_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "请用 root 执行：sudo bash $0"
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

ensure_tools_basic() {
  # 基础工具（jq/iproute2/curl）用于改 json / 获取内网 ip / 下载配置
  if ! need_cmd apt-get; then
    echo "[!] 当前脚本只支持 Debian/Ubuntu（需要 apt-get）。"
    exit 1
  fi
  apt-get update -y
  apt-get install -y ca-certificates curl jq iproute2 gnupg >/dev/null
}

ensure_docker_stack() {
  ensure_tools_basic

  # 1) docker 命令不存在：优先安装 docker.io（发行版仓库，稳）
  if ! need_cmd docker; then
    echo "[*] 未检测到 docker，开始安装（docker.io / docker-compose）..."
    apt-get update -y
    apt-get install -y docker.io docker-compose containerd >/dev/null
  fi

  # 2) 启动 daemon（dockerd）
  if need_cmd systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service docker start >/dev/null 2>&1 || true
  fi

  # 3) 确认 daemon 是否可用
  if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker daemon 不可用。请检查："
    if need_cmd systemctl; then
      echo "    systemctl status docker --no-pager"
      echo "    journalctl -u docker -n 80 --no-pager"
    else
      echo "    service docker status"
    fi
    exit 1
  fi

  # 4) 选择 compose 命令（优先 docker compose）
  if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
  elif need_cmd docker-compose; then
    COMPOSE="docker-compose"
  else
    echo "[*] 未检测到 compose，安装 docker-compose..."
    apt-get update -y
    apt-get install -y docker-compose >/dev/null
    COMPOSE="docker-compose"
  fi

  echo "[*] 使用 compose：${COMPOSE}"
}

gen_guid() {
  # 生成 {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} 大写 GUID
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

detect_lan_ip() {
  # 获取默认路由出口的内网 IPv4
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
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
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/99-openppp2.conf
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
  local image="$1"
  # client 使用 host 网络 + TUN 设备 + NET_ADMIN
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
      - "--bypass-iplist-nic=ens192"
      - "--bypass-iplist-ngw"
      - "192.168.88.1"
EOF
}

setup_systemd_weekly_update() {
  echo
  echo "[*] 设置 systemd 每周自动更新（拉最新镜像并重启 openppp2）"

  local oncal
  prompt oncal "请输入 OnCalendar（按周）表达式" "Sun *-*-* 03:00:00"

  # 更新脚本：pull + up -d（只更新 openppp2 服务）
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

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now openppp2-update.timer >/dev/null 2>&1 || true
}

do_install() {
  ensure_docker_stack

  echo
  echo "请选择："
  echo "1) 服务端"
  echo "2) 客户端"
  local ROLE
  prompt ROLE "输入 1 或 2" "1"

  local IMAGE BASE_URL
  prompt IMAGE "请输入镜像地址" "$IMAGE_DEFAULT"
  prompt BASE_URL "基准配置文件URL（appsettings.base.json raw 链接）" "$BASE_CFG_URL_DEFAULT"

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
    local SERVER_IP lan_ip guid
    prompt SERVER_IP "请输入服务端IP（用于 client.server）" ""

    guid="$(gen_guid)"
    lan_ip="$(detect_lan_ip || true)"
    if [[ -z "${lan_ip:-}" ]]; then
      echo "[!] 没检测到客户端内网IP，你可以手动输入。"
      prompt lan_ip "请输入客户端内网IP（用于 http-proxy/socks-proxy bind）" ""
    else
      echo "[*] 检测到客户端内网IP: ${lan_ip}"
    fi

    jq --arg srv "ppp://${SERVER_IP}:20000/" \
      --arg guid "$guid" \
      --arg lan "$lan_ip" \
      ' .client.server=$srv
        | .client.guid=$guid
        | .client["http-proxy"].bind=$lan
        | .client["socks-proxy"].bind=$lan ' \
      appsettings.base.json > appsettings.json

    # 这两个文件如果用户不提供也不影响启动，先给空文件
    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    enable_ip_forward_host
    write_compose_client "$IMAGE"

  else
    echo "输入错误，只能是 1 或 2"
    exit 1
  fi

  echo
  echo "[*] 启动 openppp2..."
  cd "$APP_DIR"
  ${COMPOSE} up -d

  setup_systemd_weekly_update

  echo
  echo "完成！"
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE} logs -f openppp2"
  echo "查看定时器：systemctl list-timers --all | grep openppp2"
  echo "手动触发更新：systemctl start openppp2-update.service"
}

do_uninstall() {
  ensure_docker_stack

  echo "[*] 停止/禁用定时器..."
  systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true

  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh || true
  systemctl daemon-reload >/dev/null 2>&1 || true

  # 清理旧的 watchtower（如果曾经用过）
  docker rm -f watchtower 2>/dev/null || true

  if [[ -d "$APP_DIR" ]]; then
    cd "$APP_DIR"
    echo "[*] 停止并删除容器..."
    ${COMPOSE} down --remove-orphans >/dev/null 2>&1 || true
  fi

  echo "[*] 删除目录 ${APP_DIR} ..."
  rm -rf "$APP_DIR"

  echo "卸载完成（Docker 本身未卸载）。"
}

main() {
  as_root

  echo "请选择："
  echo "1) 安装 openppp2"
  echo "2) 卸载 openppp2"
  local ACTION
  prompt ACTION "输入 1 或 2" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    *) echo "输入错误"; exit 1 ;;
  esac
}

main "$@"

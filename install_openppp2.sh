#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
BASE_CFG_URL_DEFAULT="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"
IMAGE_DEFAULT="ghcr.io/lucifer988/openppp2:latest"

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

install_docker_if_needed() {
  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    return
  fi

  echo "[*] 安装 Docker / docker compose..."
  apt-get update
  apt-get install -y ca-certificates curl gnupg jq iproute2

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

gen_guid() {
  # 不依赖 uuidgen，避免缺包
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

detect_lan_ip() {
  # 用 route get 获取 src，更稳
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  echo "${ip:-}"
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

  watchtower:
    image: containrrr/watchtower:latest
    container_name: watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --cleanup --interval 300 openppp2
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
    sysctls:
      - net.ipv4.ip_forward=1
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
      - "--bypass-iplist-ngw=192.168.88.1"

  watchtower:
    image: containrrr/watchtower:latest
    container_name: watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: --cleanup --interval 300 openppp2
YAML
}

do_install() {
  install_docker_if_needed

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
  curl -fsSL "$BASE_CFG_URL" -o appsettings.base.json

  if [[ "$ROLE" == "1" ]]; then
    prompt IPADDR "请输入您的IP地址（服务端对外 IP）" ""
    jq --arg ip "$IPADDR" \
      '.ip.public=$ip | .ip.interface=$ip' \
      appsettings.base.json > appsettings.json
    write_compose_server "$IMAGE"

  elif [[ "$ROLE" == "2" ]]; then
    prompt SERVER_IP "请输入服务端IP（用于 client.server）" ""
    local_guid="$(gen_guid)"

    lan_ip="$(detect_lan_ip)"
    if [[ -z "$lan_ip" ]]; then
      echo "[!] 没检测到内网IP，你可以手动输入。"
      prompt lan_ip "请输入客户端内网IP（用于 http-proxy/socks-proxy bind）" ""
    else
      echo "[*] 检测到客户端内网IP: ${lan_ip}"
    fi

    jq --arg srv "ppp://${SERVER_IP}:20000/" \
       --arg guid "$local_guid" \
       --arg lan "$lan_ip" \
      '
      .client.server=$srv
      | .client.guid=$guid
      | .client["http-proxy"].bind=$lan
      | .client["socks-proxy"].bind=$lan
      ' appsettings.base.json > appsettings.json

    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    write_compose_client "$IMAGE"
  else
    echo "输入错误，只能是 1 或 2"
    exit 1
  fi

  echo
  echo "[*] 启动 openppp2..."
  docker compose up -d

  echo
  echo "完成！"
  echo "配置目录：$APP_DIR"
  echo "查看日志：cd $APP_DIR && docker compose logs -f openppp2"
}

do_uninstall() {
  if [[ -d "$APP_DIR" ]]; then
    cd "$APP_DIR"
    echo "[*] 停止并删除容器..."
    docker compose down --remove-orphans || true
  fi
  echo "[*] 删除目录 $APP_DIR ..."
  rm -rf "$APP_DIR"
  echo "卸载完成（Docker 本身未卸载）。"
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
    *) echo "输入错误"; exit 1 ;;
  esac
}

main "$@"

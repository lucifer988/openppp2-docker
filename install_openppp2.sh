#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
BASE_CFG_URL_DEFAULT="https://raw.githubusercontent.com/<YOUR_GH_USER>/<YOUR_REPO>/main/appsettings.base.json"

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
  apt-get install -y ca-certificates curl gnupg jq

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
  local u
  u="$(uuidgen | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

detect_lan_ip() {
  # 取默认路由网卡的 IPv4 地址
  local ifname ip
  ifname="$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $5; exit}')"
  if [[ -z "$ifname" ]]; then
    echo ""
    return
  fi
  ip="$(ip -4 addr show dev "$ifname" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
  echo "$ip"
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
    # 服务端启动命令：./ppp
    # Dockerfile 里 ENTRYPOINT 是 ./ppp，这里不需要额外 command
YAML

  # 自动更新（你说不需要手动“更新”选项，所以默认开启）
  cat >> "$COMPOSE_FILE" <<'YAML'

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

  # 你的镜像（由 GitHub Actions 自动构建并推送到 GHCR）
  prompt IMAGE "请输入镜像地址（例如 ghcr.io/<user>/openppp2:latest）" "ghcr.io/<user>/openppp2:latest"

  # 基准配置文件来源：默认从你仓库 raw 下载
  prompt BASE_CFG_URL "基准配置文件URL（appsettings.base.json 的 raw 链接）" "$BASE_CFG_URL_DEFAULT"

  echo "[*] 下载基准配置..."
  curl -fsSL "$BASE_CFG_URL" -o appsettings.base.json

  if [[ "$ROLE" == "1" ]]; then
    # 服务端：只改 ip.public / ip.interface
    prompt IPADDR "请输入您的IP地址（服务端对外 IP）" ""
    jq --arg ip "$IPADDR" \
      '.ip.public=$ip | .ip.interface=$ip' \
      appsettings.base.json > appsettings.json

    write_compose_server "$IMAGE"

  elif [[ "$ROLE" =]()]()

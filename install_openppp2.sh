#!/usr/bin/env bash
# openppp2-docker hotfix installer
# Version: 2.3.2-hotfix
#
# 修复点：
# 1) apt update 被 Caddy 源 NO_PUBKEY 拖垮时，自动禁用坏的 Caddy 源并重试
# 2) /opt/openppp2/appsettings.json 被 Docker/Compose 误创建成目录时，自动备份挪走
# 3) docker compose 使用数组执行，不再把 "docker compose" 当成单个命令
# 4) 本地构建默认使用 openppp2 upstream 1.0.0.26151，可用 OPENPPP2_ZIP_URL 覆盖
# 5) 默认使用 seccomp=unconfined，避免过严 seccomp profile 导致容器无法启动
# 6) compose up 默认加 --force-recreate，确保修改 compose 后容器按新配置重建

set -euo pipefail

VERSION="2.3.2-hotfix"
APP_DIR="${OPENPPP2_APP_DIR:-/opt/openppp2}"
BACKUP_DIR="${APP_DIR}/backups"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"

DEFAULT_IMAGE_REPO="${OPENPPP2_IMAGE_REPO:-ghcr.io/lucifer988/openppp2}"
DEFAULT_IMAGE_TAG="${OPENPPP2_IMAGE_TAG:-latest}"
DEFAULT_IMAGE="${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}"
OPENPPP2_ZIP_URL="${OPENPPP2_ZIP_URL:-https://github.com/liulilittle/openppp2/releases/download/1.0.0.26151/openppp2-linux-amd64-simd.zip}"

APT_TIMEOUT="${APT_TIMEOUT:-180}"
NET_TIMEOUT="${NET_TIMEOUT:-60}"
COMPOSE_PULL_TIMEOUT="${COMPOSE_PULL_TIMEOUT:-600}"
COMPOSE_UP_TIMEOUT="${COMPOSE_UP_TIMEOUT:-180}"
ALLOW_LOCAL_BUILD="${ALLOW_LOCAL_BUILD:-yes}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_CFG_SOURCE="${SCRIPT_DIR}/appsettings.base.json"

COMPOSE=()

info() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die() { echo "[x] $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }

prompt() {
  local __var="$1" text="$2" default="${3:-}" value
  if [[ -n "${!__var:-}" ]]; then
    return 0
  fi
  if [[ -n "$default" ]]; then
    read -r -p "${text} [${default}]: " value || true
    value="${value:-$default}"
  else
    read -r -p "${text}: " value || true
  fi
  printf -v "$__var" '%s' "$value"
}

prompt_port() {
  local __var="$1" text="$2" default="${3:-20000}" value
  while true; do
    value=""
    prompt value "$text" "$default"
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )); then
      printf -v "$__var" '%s' "$value"
      return 0
    fi
    warn "端口必须是 1-65535 的数字"
  done
}

backup_path_if_exists() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local dst="${path}.bak.${ts}"
  info "发现已有路径：${path}"
  info "备份/挪走到：${dst}"
  mv "$path" "$dst"
}

fix_appsettings_directory_if_needed() {
  local cfg="$1"
  if [[ -d "${APP_DIR}/${cfg}" ]]; then
    local dst="${APP_DIR}/${cfg}.dir.bak.$(date +%Y%m%d_%H%M%S)"
    warn "${APP_DIR}/${cfg} 当前是目录，正常应该是 JSON 文件。"
    warn "这通常是 Docker/Compose 在配置文件不存在时自动创建宿主机目录造成的。"
    info "正在挪走错误目录：${dst}"
    mv "${APP_DIR}/${cfg}" "$dst"
  fi
}

apt_update_safe() {
  local log="/tmp/openppp2-apt-update.log"
  rm -f "$log"
  info "更新软件包列表（最多 ${APT_TIMEOUT}s）..."
  if timeout "$APT_TIMEOUT" apt-get update -o Acquire::ForceIPv4=true 2>&1 | tee "$log"; then
    return 0
  fi

  if grep -qiE 'cloudsmith|caddy|ABA1F9B8875A6661|NO_PUBKEY' "$log"; then
    warn "检测到 Caddy/Cloudsmith 源签名问题，正在临时禁用 /etc/apt/sources.list.d/*caddy* 后重试。"
    mkdir -p /root/disabled-apt-sources
    local moved=0
    for f in /etc/apt/sources.list.d/*caddy*; do
      [[ -e "$f" ]] || continue
      mv "$f" "/root/disabled-apt-sources/$(basename "$f").disabled.$(date +%Y%m%d_%H%M%S)"
      moved=1
    done
    if [[ "$moved" -eq 1 ]]; then
      timeout "$APT_TIMEOUT" apt-get update -o Acquire::ForceIPv4=true
      return 0
    fi
  fi

  warn "apt-get update 失败，最后 30 行日志："
  tail -n 30 "$log" >&2 || true
  return 1
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive timeout "$APT_TIMEOUT" apt-get install -y --no-install-recommends "$@"
}

ensure_basic_tools() {
  local missing=()
  for c in curl jq tar ip awk sed grep ss shuf; do
    need_cmd "$c" || missing+=("$c")
  done
  if (( ${#missing[@]} > 0 )); then
    step "安装基础工具：${missing[*]}"
    apt_update_safe || true
    apt_install curl jq tar iproute2 gawk sed grep ca-certificates util-linux || die "基础工具安装失败"
  fi
}

ensure_docker() {
  if need_cmd docker && docker info >/dev/null 2>&1; then
    info "Docker 已安装并可用：$(docker --version)"
    return 0
  fi

  if need_cmd docker; then
    warn "docker 命令存在，但 daemon 当前不可用，尝试启动 docker.service。"
    systemctl enable --now docker >/dev/null 2>&1 || true
    sleep 2
    docker info >/dev/null 2>&1 && return 0
  fi

  step "安装 Docker / Compose"
  apt_update_safe || true
  apt_install docker.io docker-compose-v2 || apt_install docker.io docker-compose-plugin || apt_install docker.io docker-compose || die "Docker 安装失败"
  systemctl enable --now docker >/dev/null 2>&1 || true

  local waited=0
  until docker info >/dev/null 2>&1; do
    sleep 1
    waited=$((waited + 1))
    (( waited >= 30 )) && die "Docker daemon 启动后 30 秒仍不可用，请检查：journalctl -u docker -n 80"
  done
  info "Docker 就绪：$(docker --version)"
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif need_cmd docker-compose && docker-compose version >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    die "找不到 docker compose 或 docker-compose"
  fi
  info "使用 Compose 命令：${COMPOSE[*]}"
}

compose_do() {
  "${COMPOSE[@]}" "$@"
}

compose_timeout() {
  local seconds="$1"
  shift
  timeout "$seconds" "${COMPOSE[@]}" "$@"
}

copy_base_config() {
  mkdir -p "$APP_DIR"
  if [[ -f "$BASE_CFG_SOURCE" ]]; then
    cp "$BASE_CFG_SOURCE" "${APP_DIR}/appsettings.base.json"
  else
    die "缺少 ${BASE_CFG_SOURCE}"
  fi
}

random_free_port() {
  for _ in $(seq 1 100); do
    local p
    p="$(shuf -i 10000-60000 -n 1)"
    if ! ss -tuln | awk '{print $5}' | grep -qE ":${p}$"; then
      echo "$p"
      return 0
    fi
  done
  die "无法找到空闲端口"
}

detect_net() {
  local nic="" lan="" gw=""
  nic="$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' || true)"
  gw="$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' || true)"
  if [[ -n "$nic" ]]; then
    lan="$(ip -4 addr show dev "$nic" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1 || true)"
  fi
  echo "${lan}|${nic}|${gw}"
}

make_server_config() {
  local cfg="$1" public_ip="$2" bind_ip="$3"
  fix_appsettings_directory_if_needed "$cfg"
  [[ -f "${APP_DIR}/${cfg}" ]] && cp "${APP_DIR}/${cfg}" "${APP_DIR}/${cfg}.bak.$(date +%Y%m%d_%H%M%S)"
  jq --arg ip "$public_ip" --arg bind "$bind_ip" \
    '.ip.public=$ip | .ip.interface=$bind' \
    "${APP_DIR}/appsettings.base.json" > "${APP_DIR}/${cfg}"
}

make_client_config() {
  local cfg="$1" server_ip="$2" server_port="$3" lan="$4" hport="$5" sport="$6"
  fix_appsettings_directory_if_needed "$cfg"
  [[ -f "${APP_DIR}/${cfg}" ]] && cp "${APP_DIR}/${cfg}" "${APP_DIR}/${cfg}.bak.$(date +%Y%m%d_%H%M%S)"
  local guid
  guid="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  jq --arg srv "ppp://${server_ip}:${server_port}/" \
     --arg guid "{$guid}" \
     --arg lan "$lan" \
     --argjson hport "$hport" \
     --argjson sport "$sport" \
     '.client.server=$srv
      | .client.guid=$guid
      | .client["http-proxy"].bind=$lan
      | .client["socks-proxy"].bind=$lan
      | .client["http-proxy"].port=$hport
      | .client["socks-proxy"].port=$sport' \
    "${APP_DIR}/appsettings.base.json" > "${APP_DIR}/${cfg}"
}

write_compose_server() {
  local image="$1" cfg="$2"
  local tcp_port udp_port
  tcp_port="$(jq -r '.tcp.listen.port // 20000' "${APP_DIR}/${cfg}")"
  udp_port="$(jq -r '.udp.listen.port // 20000' "${APP_DIR}/${cfg}")"

  cat > "$COMPOSE_FILE" <<YAML
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    init: true
    ports:
      - "${tcp_port}:${tcp_port}/tcp"
      - "${udp_port}:${udp_port}/udp"
    volumes:
      - type: bind
        source: ${APP_DIR}/${cfg}
        target: /opt/openppp2/appsettings.json
        read_only: true
        bind:
          create_host_path: false
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - NET_BIND_SERVICE
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "5"
YAML
  echo "server" > "${APP_DIR}/.role"
  echo "openppp2" > "${APP_DIR}/.client_main_service"
}

write_compose_client() {
  local image="$1" svc="$2" cfg="$3"
  cat > "$COMPOSE_FILE" <<YAML
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
    init: true
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - type: bind
        source: ${APP_DIR}/${cfg}
        target: /opt/openppp2/appsettings.json
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: ${APP_DIR}/ip.txt
        target: /opt/openppp2/ip.txt
        read_only: false
        bind:
          create_host_path: false
      - type: bind
        source: ${APP_DIR}/dns-rules.txt
        target: /opt/openppp2/dns-rules.txt
        read_only: false
        bind:
          create_host_path: false
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - NET_BIND_SERVICE
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "5"
YAML
  echo "client" > "${APP_DIR}/.role"
  echo "$svc" > "${APP_DIR}/.client_main_service"
}

pull_or_build() {
  local image="$1"
  step "拉取镜像（最多 ${COMPOSE_PULL_TIMEOUT}s）"
  local log="/tmp/openppp2-compose-pull.log"
  rm -f "$log"
  if compose_timeout "$COMPOSE_PULL_TIMEOUT" -f "$COMPOSE_FILE" pull 2>&1 | tee "$log"; then
    info "镜像拉取完成"
    return 0
  fi

  warn "compose pull 失败，最后 20 行日志："
  tail -n 20 "$log" >&2 || true

  [[ "$ALLOW_LOCAL_BUILD" == "yes" ]] || die "镜像拉取失败，且 ALLOW_LOCAL_BUILD=no"

  step "回退：本机构建镜像"
  info "构建目标镜像：${image}"
  info "openppp2 ZIP：${OPENPPP2_ZIP_URL}"
  timeout 900 docker build \
    --build-arg "OPENPPP2_ZIP_URL=${OPENPPP2_ZIP_URL}" \
    -t "$image" "$SCRIPT_DIR" || die "本地 docker build 失败"
}

compose_up() {
  step "启动容器（最多 ${COMPOSE_UP_TIMEOUT}s）"
  local log="/tmp/openppp2-compose-up.log"
  rm -f "$log"

  # 如果已有同名旧容器，先用 compose down 尝试清理；随后 force-recreate 确保新 compose 安全参数生效。
  compose_do -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true

  compose_timeout "$COMPOSE_UP_TIMEOUT" -f "$COMPOSE_FILE" up -d --force-recreate --remove-orphans 2>&1 | tee "$log" || {
    warn "compose up 失败，最后 30 行日志："
    tail -n 30 "$log" >&2 || true
    warn "自动输出诊断信息："
    docker ps -a --filter name=openppp2 || true
    docker inspect openppp2 --format '{{json .State}}' 2>/dev/null || true
    die "容器启动失败"
  }
}

health_check() {
  local svc="$1"
  info "等待容器 ${svc} 进入运行状态..."
  for i in $(seq 1 40); do
    if docker inspect "$svc" >/dev/null 2>&1; then
      local running
      running="$(docker inspect --format '{{.State.Running}}' "$svc" 2>/dev/null || echo false)"
      if [[ "$running" == "true" ]]; then
        info "容器 ${svc} 已运行"
        return 0
      fi
    fi
    sleep 1
  done
  warn "容器 ${svc} 未确认运行，请查看日志：docker logs ${svc} --tail=100"
}

do_install_server() {
  ensure_basic_tools
  ensure_docker
  detect_compose
  copy_base_config

  local IMAGE="$DEFAULT_IMAGE"
  prompt IMAGE "请输入镜像地址" "$DEFAULT_IMAGE"

  local APP_CFG_NAME="appsettings.json"
  prompt APP_CFG_NAME "请输入服务端配置文件名" "appsettings.json"

  local autoip=""
  info "尝试自动检测公网 IP（最多 ${NET_TIMEOUT}s）..."
  autoip="$(timeout "$NET_TIMEOUT" curl -4 -fsS https://api.ipify.org 2>/dev/null || true)"

  local SERVER_PUBLIC_IP="${SERVER_PUBLIC_IP:-}"
  prompt SERVER_PUBLIC_IP "请输入服务端对外（公网）IP" "$autoip"
  [[ -z "$SERVER_PUBLIC_IP" ]] && die "服务端公网 IP 不能为空"

  local SERVER_BIND_IP="${SERVER_BIND_IP:-}"
  prompt SERVER_BIND_IP "请输入服务端监听 bind IP（NAT 填内网 IP，直连填公网 IP）" "$SERVER_PUBLIC_IP"
  [[ -z "$SERVER_BIND_IP" ]] && die "服务端监听 IP 不能为空"

  make_server_config "$APP_CFG_NAME" "$SERVER_PUBLIC_IP" "$SERVER_BIND_IP"
  write_compose_server "$IMAGE" "$APP_CFG_NAME"
  pull_or_build "$IMAGE"
  compose_up
  health_check openppp2

  echo
  echo "===== 服务端安装完成 ====="
  echo "配置目录：${APP_DIR}"
  echo "配置文件：${APP_DIR}/${APP_CFG_NAME}"
  echo "查看容器：cd ${APP_DIR} && ${COMPOSE[*]} ps"
  echo "查看日志：docker logs openppp2 --tail=100 -f"
}

do_install_client() {
  [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在，client 模式需要 TUN。可尝试：sudo modprobe tun"

  ensure_basic_tools
  ensure_docker
  detect_compose
  copy_base_config

  local IMAGE="$DEFAULT_IMAGE"
  prompt IMAGE "请输入镜像地址" "$DEFAULT_IMAGE"

  local APP_CFG_NAME="appsettings.json"
  prompt APP_CFG_NAME "请输入客户端配置文件名" "appsettings.json"

  local MAIN_SERVICE_NAME="openppp2"
  prompt MAIN_SERVICE_NAME "请输入主客户端实例名称" "openppp2"

  local SERVER_IP="${SERVER_IP:-}"
  prompt SERVER_IP "请输入服务端 IP" ""
  [[ -z "$SERVER_IP" ]] && die "服务端 IP 不能为空"

  local SERVER_PORT="${SERVER_PORT:-}"
  prompt_port SERVER_PORT "请输入服务端端口" "20000"

  info "自动探测客户端网络环境..."
  local netinfo lan nic gw
  netinfo="$(detect_net)"
  lan="${netinfo%%|*}"
  netinfo="${netinfo#*|}"
  nic="${netinfo%%|*}"
  gw="${netinfo#*|}"

  prompt lan "请输入客户端内网 IP" "$lan"
  [[ -z "$lan" ]] && die "客户端内网 IP 不能为空"

  local HTTP_PORT SOCKS_PORT
  HTTP_PORT="$(random_free_port)"
  SOCKS_PORT="$(random_free_port)"
  while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do SOCKS_PORT="$(random_free_port)"; done

  mkdir -p "$APP_DIR"
  [[ -f "${APP_DIR}/ip.txt" ]] || : > "${APP_DIR}/ip.txt"
  [[ -f "${APP_DIR}/dns-rules.txt" ]] || : > "${APP_DIR}/dns-rules.txt"

  make_client_config "$APP_CFG_NAME" "$SERVER_IP" "$SERVER_PORT" "$lan" "$HTTP_PORT" "$SOCKS_PORT"
  write_compose_client "$IMAGE" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME"
  pull_or_build "$IMAGE"
  compose_up
  health_check "$MAIN_SERVICE_NAME"

  echo
  echo "===== 客户端安装完成 ====="
  echo "配置目录：${APP_DIR}"
  echo "SOCKS5：${lan}:${SOCKS_PORT}"
  echo "HTTP  ：${lan}:${HTTP_PORT}"
}

do_install() {
  echo "=============================="
  echo "  请选择安装/部署角色："
  echo "    1) 服务端（Server）"
  echo "    2) 客户端（Client）"
  echo "=============================="
  local ROLE="${ROLE:-}"
  prompt ROLE "请输入数字选择（1 或 2）" "1"
  case "$ROLE" in
    1) do_install_server ;;
    2) do_install_client ;;
    *) die "角色选择错误，只能输入 1 或 2" ;;
  esac
}

do_uninstall() {
  ensure_docker || true
  detect_compose || true
  if [[ -f "$COMPOSE_FILE" ]]; then
    step "停止并删除 compose 容器"
    (cd "$APP_DIR" && compose_do -f "$COMPOSE_FILE" down --remove-orphans) || true
  fi

  local KEEP_BACKUP="yes"
  prompt KEEP_BACKUP "是否保留 backups 目录？(yes/no)" "yes"
  if [[ "$KEEP_BACKUP" == "yes" && -d "$BACKUP_DIR" ]]; then
    local tmp="/tmp/openppp2-backups-$(date +%Y%m%d_%H%M%S)"
    mv "$BACKUP_DIR" "$tmp"
    rm -rf "$APP_DIR"
    mkdir -p "$APP_DIR"
    mv "$tmp" "$BACKUP_DIR"
  else
    rm -rf "$APP_DIR"
  fi
  echo "卸载完成。"
}

do_show_info() {
  [[ -d "$APP_DIR" ]] || die "${APP_DIR} 不存在"
  echo "配置目录：${APP_DIR}"
  echo
  ls -lah "$APP_DIR"
  echo
  if [[ -f "${APP_DIR}/.role" ]]; then
    echo "角色：$(cat "${APP_DIR}/.role")"
  fi
  for f in "$APP_DIR"/appsettings*.json; do
    [[ -f "$f" ]] || continue
    echo
    echo "配置文件：$f"
    jq -r '
      "server: " + (.client.server // "N/A"),
      "http : " + ((.client["http-proxy"].bind // "N/A") + ":" + ((.client["http-proxy"].port // "N/A")|tostring)),
      "socks: " + ((.client["socks-proxy"].bind // "N/A") + ":" + ((.client["socks-proxy"].port // "N/A")|tostring)),
      "public ip: " + (.ip.public // "N/A"),
      "bind ip  : " + (.ip.interface // "N/A")
    ' "$f" 2>/dev/null || true
  done
}

do_backup() {
  [[ -d "$APP_DIR" ]] || die "${APP_DIR} 不存在"
  mkdir -p "$BACKUP_DIR"
  local out="${BACKUP_DIR}/openppp2-config-$(date +%Y%m%d_%H%M%S).tar.gz"
  tar --exclude="$BACKUP_DIR" -czf "$out" -C "$APP_DIR" .
  echo "备份完成：$out"
}

do_restore() {
  [[ -d "$BACKUP_DIR" ]] || die "没有找到备份目录：${BACKUP_DIR}"
  local latest
  latest="$(ls -1t "$BACKUP_DIR"/openppp2-config-*.tar.gz 2>/dev/null | head -1 || true)"
  [[ -n "$latest" ]] || die "没有找到备份文件"
  local RESTORE="no"
  prompt RESTORE "确认恢复最新备份 ${latest} ? (yes/no)" "no"
  [[ "$RESTORE" == "yes" ]] || die "已取消"
  tar -xzf "$latest" -C "$APP_DIR"
  echo "恢复完成：$latest"
}

do_not_implemented_add_client() {
  warn "这个 hotfix 包主要修复安装路径；新增多客户端实例建议先完成主客户端安装后复制 docker-compose.yml 手动添加服务。"
  warn "为了避免误改现有路由和 TUN，本 hotfix 版没有自动追加多实例。"
}

main() {
  echo "=============================="
  echo "  openppp2 一键部署脚本 v${VERSION}"
  echo "=============================="
  echo "请选择操作："
  echo "  1) 安装 openppp2"
  echo "  2) 卸载 openppp2"
  echo "  3) 新增 openppp2 客户端实例"
  echo "  4) 查看客户端配置和代理信息"
  echo "  5) 删除客户端实例/配置"
  echo "  6) 备份当前配置文件"
  echo "  7) 回滚（恢复最新备份）"
  echo "=============================="

  local ACTION="${ACTION:-}"
  prompt ACTION "请输入数字选择（1 / 2 / 3 / 4 / 5 / 6 / 7）" "1"
  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_not_implemented_add_client ;;
    4) ensure_basic_tools; do_show_info ;;
    5) do_not_implemented_add_client ;;
    6) do_backup ;;
    7) do_restore ;;
    *) die "输入错误，只能是 1 / 2 / 3 / 4 / 5 / 6 / 7" ;;
  esac
}

main "$@"

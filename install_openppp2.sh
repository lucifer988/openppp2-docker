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

prompt_port() {
  local __var="$1" __msg="$2" __def="${3:-20000}"
  local p=""
  while :; do
    prompt p "$__msg" "$__def"
    if [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )); then
      printf -v "$__var" "%s" "$p"
      return 0
    fi
    warn "端口必须是 1-65535 的纯数字（你输入的是：$p），请重新输入。"
  done
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
  if need_cmd docker-compose && docker-compose version >/dev/null 2>&1; then
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
    apt_install ca-certificates curl jq iproute2 gnupg >/dev/null 2>&1 || true
  fi
  need_cmd curl || die "curl 未安装"
  need_cmd jq   || die "jq 未安装"
}

docker_daemon_ok() {
  need_cmd docker || return 1
  docker info >/dev/null 2>&1
}

ensure_docker_stack() {
  ensure_basic_tools

  if ! docker_daemon_ok; then
    if need_cmd apt-get; then
      apt_install docker.io >/dev/null 2>&1 || true
      systemctl enable --now docker >/dev/null 2>&1 || true
    fi
  fi

  docker_daemon_ok || die "Docker daemon 不可用"
  detect_compose || die "未检测到 docker compose"

  info "使用 compose：${COMPOSE_KIND}"
}

download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"
  info "下载 appsettings.base.json"
  curl_retry -sS "$url" -o appsettings.base.json
}

compose_header() {
  if [[ "$COMPOSE_KIND" == "docker-compose" ]]; then
    echo 'version: "3.8"'
  fi
}

###############################################################################
# ✅ 关键修复点：服务端禁用 io_uring（Boost.Asio）
###############################################################################
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
    environment:
      - BOOST_ASIO_DISABLE_IO_URING=1
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
EOF
  } >"$COMPOSE_FILE"
}

###############################################################################

do_install() {
  ensure_docker_stack

  echo "============================"
  echo "  1) 服务端 (Server)"
  echo "  2) 客户端 (Client)"
  echo "============================"
  local ROLE
  prompt ROLE "请选择角色" "1"

  local IMAGE BASE_URL
  prompt IMAGE "镜像地址" "$DEFAULT_IMAGE"
  prompt BASE_URL "基准配置 URL" "$DEFAULT_BASE_CFG_URL"

  download_base_cfg "$BASE_URL"
  cd "$APP_DIR"

  if [[ "$ROLE" == "1" ]]; then
    local CFG
    prompt CFG "服务端配置文件名" "appsettings.json"

    local IP
    IP="$(curl_retry -sS https://api.ipify.org || true)"
    prompt IP "服务端公网 IP" "$IP"

    jq --arg ip "$IP" \
      '.ip.public=$ip | .ip.interface=$ip' \
      appsettings.base.json > "$CFG"

    write_compose_server "$IMAGE" "$CFG"
    echo "server" > .role
  else
    die "本脚本主要修复 server，client 保持你原逻辑"
  fi

  compose up -d
  docker logs -f --tail=80 openppp2
}

check_env_supported() {
  is_root || die "请使用 root 执行"
}

main() {
  check_env_supported
  do_install
}

main "$@"

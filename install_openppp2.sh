#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
IMAGE_DEFAULT="ghcr.io/lucifer988/openppp2:latest"
CONTAINER_DEFAULT="openppp2"
PORT_DEFAULT="20000"

log()  { echo -e "[*] $*"; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }

has_systemd() { [[ -d /run/systemd/system ]] && need_cmd systemctl; }

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

apt_force_ipv4() {
  if ! need_cmd apt-get; then return 0; fi
  local cfg="/etc/apt/apt.conf.d/99force-ipv4"
  if [[ -f "$cfg" ]] && grep -q 'Acquire::ForceIPv4' "$cfg" 2>/dev/null; then
    log "APT 已设置为强制使用 IPv4。"
    return 0
  fi
  log "为 APT 启用 IPv4 优先（避免 IPv6 卡住）..."
  cat >"$cfg" <<'EOF'
Acquire::ForceIPv4 "true";
EOF
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

curl_retry() {
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 --max-time 180 "$@"
}

detect_os() {
  # echo "debian|bookworm" or "ubuntu|jammy"
  local id="" codename=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    codename="${VERSION_CODENAME:-}"
  fi
  echo "${id}|${codename}"
}

start_docker_service() {
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service docker start >/dev/null 2>&1 || true
  fi
}

docker_ready() {
  need_cmd docker || return 1
  docker info >/dev/null 2>&1
}

docker_ready_retry() {
  local i
  for i in {1..30}; do
    if docker_ready; then return 0; fi
    sleep 1
  done
  return 1
}

print_docker_diag() {
  warn "Docker 诊断信息："
  warn "环境变量：DOCKER_HOST='${DOCKER_HOST-}' DOCKER_CONTEXT='${DOCKER_CONTEXT-}'"
  if has_systemd; then
    warn "systemctl status docker："
    systemctl status docker --no-pager -l || true
    warn "journalctl -u docker（最近 120 行）："
    journalctl -u docker -n 120 --no-pager || true
  else
    warn "非 systemd 环境：请手动查看 dockerd 日志。"
  fi
  warn "尝试：docker info"
  docker info || true
}

install_docker_official() {
  # Docker 官方仓库（debian/ubuntu）
  local os id codename
  os="$(detect_os)"
  id="${os%%|*}"
  codename="${os#*|}"

  [[ "$id" == "debian" || "$id" == "ubuntu" ]] || return 1
  [[ -n "$codename" ]] || return 1

  log "检测到系统：$id $codename，使用 Docker 官方仓库安装..."

  apt_install ca-certificates curl gnupg

  install -m 0755 -d /etc/apt/keyrings
  if [[ "$id" == "debian" ]]; then
    curl_retry -fsSL "https://download.docker.com/linux/debian/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $codename stable
EOF
  else
    curl_retry -fsSL "https://download.docker.com/linux/ubuntu/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $codename stable
EOF
  fi

  apt-get update -y
  # docker-ce + compose plugin
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  start_docker_service
  docker_ready_retry
}

install_docker_distro() {
  # fallback: docker.io
  log "改用系统仓库安装 docker.io（fallback）..."
  apt_install ca-certificates curl
  apt_install docker.io || return 1

  # compose：优先 plugin，否则 docker-compose
  apt_install docker-compose-plugin >/dev/null 2>&1 || true
  if ! (docker compose version >/dev/null 2>&1); then
    apt_install docker-compose >/dev/null 2>&1 || true
  fi

  start_docker_service
  docker_ready_retry
}

ensure_docker() {
  apt_force_ipv4

  if docker_ready_retry; then
    log "Docker 已可用。"
  else
    warn "未检测到可用的 Docker，开始安装..."
    if ! install_docker_official; then
      warn "官方仓库安装失败/不匹配，尝试 docker.io ..."
      install_docker_distro || { print_docker_diag; die "Docker 安装/启动失败（docker info 不通）。"; }
    fi
  fi

  # 最终确保 compose 可用
  if docker compose version >/dev/null 2>&1; then
    log "已检测到：docker compose"
  elif need_cmd docker-compose && docker-compose version >/dev/null 2>&1; then
    log "已检测到：docker-compose"
  else
    # 再兜底装一次
    if need_cmd apt-get; then
      apt_install docker-compose-plugin >/dev/null 2>&1 || true
      apt_install docker-compose >/dev/null 2>&1 || true
    fi
    (docker compose version >/dev/null 2>&1) || (need_cmd docker-compose && docker-compose version >/dev/null 2>&1) || \
      die "未检测到 docker compose / docker-compose，请手动检查安装。"
  fi
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  else
    echo "docker-compose"
  fi
}

ensure_app_dir() {
  mkdir -p "$APP_DIR"
}

write_compose() {
  local image="$1" name="$2" port="$3"
  local yml="${APP_DIR}/docker-compose.yml"

  cat >"$yml" <<EOF
services:
  ${name}:
    image: ${image}
    container_name: ${name}
    restart: unless-stopped

    # 关键：解决 io_uring_queue_init: Operation not permitted
    security_opt:
      - seccomp=unconfined

    # 配置文件只读挂载
    volumes:
      - ${APP_DIR}/appsettings.json:/opt/openppp2/appsettings.json:ro

    # 端口映射
    ports:
      - "${port}:20000/tcp"
      - "${port}:20000/udp"
EOF

  log "已写入 ${yml}"
}

ensure_config() {
  local cfg="${APP_DIR}/appsettings.json"
  if [[ -f "$cfg" ]]; then
    log "检测到已有配置：${cfg}（将复用，不覆盖）"
    return 0
  fi
  warn "未检测到 ${cfg}"
  warn "你需要先把 appsettings.json 放到 ${APP_DIR}/appsettings.json"
  warn "（或者先用你的方式生成，再运行“安装/重建”）"
  die "缺少配置文件：${cfg}"
}

up_openppp2() {
  local dc
  dc="$(compose_cmd)"

  (cd "$APP_DIR" && $dc pull)
  (cd "$APP_DIR" && $dc up -d --remove-orphans)

  log "容器状态："
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed -n '1,2p'
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | grep -E "^\s*openppp2\b" || true

  log "如果外网不通，先看日志：docker logs --tail=80 ${CONTAINER_DEFAULT}"
}

install_or_rebuild() {
  ensure_docker
  ensure_app_dir

  local image name port
  prompt image "请输入镜像地址" "${IMAGE_DEFAULT}"
  prompt name "请输入容器/服务名" "${CONTAINER_DEFAULT}"
  prompt port "请输入对外端口（映射到容器 20000）" "${PORT_DEFAULT}"

  ensure_config
  write_compose "$image" "$name" "$port"
  up_openppp2
}

uninstall_openppp2() {
  local dc
  dc="$(compose_cmd)"

  if [[ -d "$APP_DIR" && -f "${APP_DIR}/docker-compose.yml" ]]; then
    (cd "$APP_DIR" && $dc down --remove-orphans) || true
  fi
  rm -rf "$APP_DIR"
  log "已卸载 openppp2（不会卸载 Docker）。"
}

show_status() {
  log "Docker 容器："
  docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | sed -n '1,60p'
  echo
  if [[ -f "${APP_DIR}/docker-compose.yml" ]]; then
    log "compose 文件：${APP_DIR}/docker-compose.yml"
  fi
  if [[ -f "${APP_DIR}/appsettings.json" ]]; then
    log "配置文件：${APP_DIR}/appsettings.json"
  fi
}

main_menu() {
  echo "=============================="
  echo "  openppp2 一键部署脚本"
  echo "=============================="
  echo "请选择操作："
  echo "  1) 安装/重建 openppp2（自动装 Docker + compose）"
  echo "  2) 卸载 openppp2（不卸载 Docker）"
  echo "  3) 查看状态（容器/端口/配置路径）"
  echo "=============================="
  local action
  prompt action "请输入数字选择（1 / 2 / 3）" "1"

  case "$action" in
    1) install_or_rebuild ;;
    2) uninstall_openppp2 ;;
    3) ensure_docker; show_status ;;
    *) die "输入错误，只能是 1 / 2 / 3。" ;;
  esac
}

main() {
  is_root || die "请用 root 执行：sudo bash $0"
  main_menu
}

main "$@"

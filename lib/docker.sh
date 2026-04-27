#!/usr/bin/env bash
# lib/docker.sh — Modular library for openppp2-docker
# Auto-refactored from install_openppp2.sh

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === compose ===
compose() {
  if [[ "$COMPOSE_KIND" == "docker compose" ]]; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}


# === detect_compose ===
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


# === start_docker_daemon_soft ===
start_docker_daemon_soft() {
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service docker start >/dev/null 2>&1 || true
  fi
}


# === docker_daemon_ok ===
docker_daemon_ok() {
  need_cmd docker || return 1
  docker info >/dev/null 2>&1
}


# === print_docker_diagnose ===
print_docker_diagnose() {
  warn "Docker 诊断信息（用于排查 docker info 失败的真实原因）："
  warn "环境变量（可能污染 docker 连接目标）："
  echo "  DOCKER_HOST=${DOCKER_HOST-}" >&2
  echo "  DOCKER_CONTEXT=${DOCKER_CONTEXT-}" >&2
  if has_systemd; then
    warn "systemctl status docker："
    systemctl status docker --no-pager -l || true
    warn "journalctl -u docker（最近 120 行）："
    journalctl -u docker -n 120 --no-pager || true
  else
    warn "非 systemd 环境：请自行查看 docker daemon 日志。"
  fi
}


# === install_docker_from_debian ===
install_docker_from_debian() {
  local install_role="${1:-unknown}"

  maybe_prompt_apt_proxy_for_client "$install_role"

  info "尝试通过 Docker 官方安装脚本安装 Docker ..."
  local docker_install_script="/tmp/get-docker.sh"

  curl_retry -fsSL https://get.docker.com -o "$docker_install_script" || die "下载 Docker 官方安装脚本失败。"
  sh "$docker_install_script" || die "执行 Docker 官方安装脚本失败。"
  rm -f "$docker_install_script" >/dev/null 2>&1 || true

  start_docker_daemon_soft
  return 0
}


# === install_docker_compose_plugin_if_missing ===
install_docker_compose_plugin_if_missing() {
  local install_role="${1:-unknown}"

  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    return 0
  fi

  if need_cmd apt-get; then
    maybe_prompt_apt_proxy_for_client "$install_role"
    info "正在安装 docker-compose-plugin..."
    apt_install docker-compose-plugin || true
  fi

  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    return 0
  fi

  if ! need_cmd docker-compose && need_cmd apt-get; then
    maybe_prompt_apt_proxy_for_client "$install_role"
    info "正在安装 docker-compose（兼容模式）..."
    apt_install docker-compose || true
  fi

  return 0
}


# === ensure_docker_stack ===
ensure_docker_stack() {
  local install_role="${1:-unknown}"

  ensure_basic_tools "$install_role"

  if docker_daemon_ok; then
    info "已检测到可用的 Docker 环境。"
  else
    if ! need_cmd docker; then
      warn "当前系统未检测到 docker，尝试通过 Docker 官方安装脚本安装 ..."
      install_docker_from_debian "$install_role" || warn "通过官方安装脚本安装 Docker 失败，请手动安装 Docker。"
    else
      warn "已检测到 docker CLI，但 daemon 当前不可用，尝试启动 docker 服务..."
      start_docker_daemon_soft
    fi
  fi

  if ! docker_daemon_ok; then
    print_docker_diagnose
    die "Docker daemon 不可用（或 docker CLI 无法连接）。请先确保 docker info 正常后再运行脚本。"
  fi

  install_docker_compose_plugin_if_missing "$install_role"

  if ! detect_compose; then
    die "未检测到 docker compose 或 docker-compose。请先安装 compose 后再运行脚本。"
  fi

  info "已选择使用 compose：${COMPOSE_KIND}"
}


# === setup_docker_proxy ===
setup_docker_proxy() {
  local proxy_ip="$1"
  local proxy_port="$2"

  if ! has_systemd; then
    warn "非 systemd 环境，无法自动配置 Docker 代理。"
    return 1
  fi

  info "配置 Docker HTTP 代理：${proxy_ip}:${proxy_port}"

  mkdir -p /etc/systemd/system/docker.service.d

  cat > /etc/systemd/system/docker.service.d/http-proxy.conf <<PROXYEOF
[Service]
Environment="HTTP_PROXY=http://${proxy_ip}:${proxy_port}"
Environment="HTTPS_PROXY=http://${proxy_ip}:${proxy_port}"
PROXYEOF

  systemctl daemon-reload
  systemctl restart docker

  sleep 2

  if ! docker_daemon_ok; then
    warn "Docker 重启后无法连接，可能代理配置有误。"
    return 1
  fi

  info "Docker 代理配置成功"
  return 0
}


# === remove_docker_proxy ===
remove_docker_proxy() {
  local restart_docker_after_remove="${1:-yes}"

  if ! has_systemd; then
    return 0
  fi

  if [[ -f /etc/systemd/system/docker.service.d/http-proxy.conf ]]; then
    info "删除 Docker 代理配置..."
    rm -f /etc/systemd/system/docker.service.d/http-proxy.conf
    systemctl daemon-reload

    if [[ "$restart_docker_after_remove" == "yes" ]]; then
      systemctl restart docker
      sleep 2
      info "Docker 代理配置已删除"
    else
      warn "已删除 Docker 代理配置文件，但未立即重启 Docker。"
      warn "当前 Docker daemon 仍可能继续使用旧代理，直到你手动执行：systemctl restart docker"
    fi
  fi
}


# === cleanup_docker_proxy_after_pull ===
cleanup_docker_proxy_after_pull() {
  local proxy_configured="${1:-0}"
  if [[ "$proxy_configured" -eq 1 ]]; then
    remove_docker_proxy "no"
  fi
}


# === health_check_one ===
health_check_one() {
  local svc="$1"
  local ok=0
  if ! docker ps --format '{{.Names}}' | grep -qx "$svc"; then
    warn "容器未运行：${svc}"
    echo "  查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs --tail=200 ${svc}" >&2
    ok=1
  fi

  if docker logs "$svc" 2>/dev/null | tail -n 200 | grep -q 'io_uring_queue_init: Operation not permitted'; then
    warn "检测到 io_uring 被拒绝（Operation not permitted）。"
    warn "请检查 seccomp 配置文件是否正确加载。"
    echo "  查看日志：docker logs --tail=200 ${svc}" >&2
    ok=1
  fi

  return $ok
}


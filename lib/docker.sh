#!/usr/bin/env bash
# lib/docker.sh — Docker 守护进程 / Compose / 代理 / 健康检查
#
# v2.3 防卡死改动：
#   1) ensure_docker 在装 docker 前检查是否已存在，已有就跳过
#   2) systemctl start docker 加 60s 超时
#   3) compose pull 用 timeout 包住（COMPOSE_PULL_TIMEOUT 默认 600s）
#   4) compose up -d 用 timeout 包住（COMPOSE_UP_TIMEOUT 默认 180s）
#   5) 拉取失败 → 触发本地 build（ALLOW_LOCAL_BUILD=yes 时）
#   6) health_check_one 显示进度，最多等 HEALTH_CHECK_TIMEOUT 秒（默认 40s）
#   7) 所有阻塞操作前打印 step()，方便用户判断卡在哪一步

SCRIPT_DIR_DOCKER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR_DOCKER}/config.sh" ]] && source "${SCRIPT_DIR_DOCKER}/config.sh"

# === detect_compose — 探测 docker compose / docker-compose ===
detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"
  elif need_cmd docker-compose; then
    COMPOSE_KIND="docker-compose"
  else
    COMPOSE_KIND=""
    return 1
  fi
  export COMPOSE_KIND
  return 0
}

# === compose <args...> — 透传执行 ===
compose() {
  if [[ -z "$COMPOSE_KIND" ]]; then
    detect_compose || die "找不到 docker compose / docker-compose 命令"
  fi
  # shellcheck disable=SC2086
  $COMPOSE_KIND "$@"
}

# === ensure_docker — 装 Docker，已有则跳过 ===
ensure_docker() {
  if need_cmd docker && docker info >/dev/null 2>&1; then
    info "Docker 已安装并可用：$(docker --version 2>/dev/null || echo unknown)"
    return 0
  fi

  if need_cmd docker; then
    info "docker 命令存在但 daemon 不通，尝试启动..."
    if has_systemd; then
      timeout 60 systemctl enable --now docker >/dev/null 2>&1 || warn "systemctl 启动 docker 失败"
    fi
    if docker info >/dev/null 2>&1; then
      info "Docker daemon 已启动"
      return 0
    fi
  fi

  step "安装 Docker（约 1-3 分钟，视网络速度）..."

  # 尝试官方一键脚本（带超时）
  if ! need_cmd docker; then
    info "下载 Docker 官方安装脚本..."
    if ! curl_retry -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
      warn "Docker 官方脚本下载失败，回退到 apt 安装 docker.io"
      apt_install docker.io docker-compose-v2 || apt_install docker.io
    else
      info "运行 Docker 安装脚本（超时 600s）..."
      if ! timeout 600 sh /tmp/get-docker.sh 2>&1 | tee /tmp/docker-install.log | grep -E '^\+' | tail -20; then
        warn "Docker 官方脚本超时或失败，回退到 apt"
        apt_install docker.io docker-compose-v2 || apt_install docker.io
      fi
      rm -f /tmp/get-docker.sh
    fi
  fi

  need_cmd docker || die "Docker 安装失败，请手动安装后重试。"

  if has_systemd; then
    info "启动 docker.service..."
    timeout 60 systemctl enable --now docker >/dev/null 2>&1 || warn "systemctl 启动 docker 失败（继续）"
  fi

  # 等 daemon 起来，最多 30s
  local waited=0
  while ! docker info >/dev/null 2>&1; do
    sleep 1
    waited=$((waited+1))
    if [[ $waited -ge 30 ]]; then
      die "Docker daemon 启动后 30s 仍不可用，请手动检查：journalctl -u docker -n 50"
    fi
  done
  info "Docker 就绪：$(docker --version)"
}

# === ensure_docker_stack <role> — 一次性把 docker + compose 准备好 ===
ensure_docker_stack() {
  local role="${1:-unknown}"
  ensure_basic_tools "$role"
  ensure_docker
  detect_compose || {
    info "未检测到 docker compose，尝试安装 docker-compose-plugin..."
    apt_install docker-compose-plugin || apt_install docker-compose
    detect_compose || die "docker compose 安装失败，请手动安装。"
  }
  info "使用 compose 命令：${COMPOSE_KIND}"
}

# === setup_docker_proxy <ip> <port> ===
# 给 Docker daemon 临时配 HTTP 代理。返回 0 成功 / 非 0 失败。
setup_docker_proxy() {
  local ip="$1" port="$2"
  has_systemd || { warn "无 systemd，跳过 Docker 代理配置"; return 1; }

  local dropdir="/etc/systemd/system/docker.service.d"
  mkdir -p "$dropdir"
  cat > "$dropdir/http-proxy.conf" <<PROXYEOF
[Service]
Environment="HTTP_PROXY=http://${ip}:${port}"
Environment="HTTPS_PROXY=http://${ip}:${port}"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
PROXYEOF

  info "重载 Docker daemon 配置（代理 http://${ip}:${port}）..."
  timeout 30 systemctl daemon-reload >/dev/null 2>&1 || true
  if ! timeout 60 systemctl restart docker >/dev/null 2>&1; then
    warn "systemctl restart docker 超时或失败"
    return 1
  fi

  # 等 daemon 恢复
  local waited=0
  while ! docker info >/dev/null 2>&1; do
    sleep 1
    waited=$((waited+1))
    [[ $waited -ge 30 ]] && { warn "Docker 配代理后启动失败"; return 1; }
  done
  return 0
}

# === cleanup_docker_proxy_after_pull <proxy_configured> ===
# 拉完镜像后删配置文件，但不立即重启 daemon，避免打断刚启动的容器。
cleanup_docker_proxy_after_pull() {
  local was_configured="${1:-0}"
  [[ "$was_configured" -eq 1 ]] || return 0
  rm -f /etc/systemd/system/docker.service.d/http-proxy.conf >/dev/null 2>&1 || true
  rmdir /etc/systemd/system/docker.service.d >/dev/null 2>&1 || true
  if has_systemd; then
    timeout 10 systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  info "已删除 Docker 代理配置文件（daemon 尚未重启以避免打断容器）"
}

# === remove_docker_proxy — 卸载时彻底清掉代理 ===
remove_docker_proxy() {
  rm -f /etc/systemd/system/docker.service.d/http-proxy.conf >/dev/null 2>&1 || true
  rmdir /etc/systemd/system/docker.service.d >/dev/null 2>&1 || true
  if has_systemd; then
    timeout 10 systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

# ============================================================
# pull_with_fallback — 拉镜像，失败就本地构建
# ============================================================
# 关键防卡死逻辑：
#   1) docker compose pull 用 timeout 包住（COMPOSE_PULL_TIMEOUT）
#   2) 拉失败且 ALLOW_LOCAL_BUILD=yes 且本地有 Dockerfile → 本地构建
#   3) 全部失败 die，不会无限等
# ============================================================
pull_with_fallback() {
  local app_dir="$1"
  safer_cd "$app_dir"

  step "拉取镜像（最多 ${COMPOSE_PULL_TIMEOUT}s）..."
  local pull_log="/tmp/openppp2-pull.log"
  rm -f "$pull_log"

  if timeout "${COMPOSE_PULL_TIMEOUT}" "$COMPOSE_KIND" pull 2>&1 | tee "$pull_log"; then
    info "镜像拉取完成"
    safer_back
    return 0
  fi

  warn "compose pull 超时或失败，最后 20 行日志："
  tail -n 20 "$pull_log" >&2 || true

  if [[ "$ALLOW_LOCAL_BUILD" != "yes" ]]; then
    safer_back
    die "镜像拉取失败，且 ALLOW_LOCAL_BUILD=no，安装中止。"
  fi

  # 本地构建：脚本目录下应有 Dockerfile
  if [[ ! -f "${SCRIPT_DIR_DOCKER}/Dockerfile" ]]; then
    safer_back
    die "镜像拉取失败，且脚本目录下没有 Dockerfile，无法本地构建。"
  fi

  step "回退方案：在本机构建镜像（约 2-5 分钟）..."

  # 解析 compose 里的 image: 字段
  local target_image
  target_image="$(grep -E '^\s+image:' docker-compose.yml | head -1 | awk '{print $2}')"
  [[ -z "$target_image" ]] && target_image="${DEFAULT_IMAGE}"

  info "本地构建目标镜像：${target_image}"
  if ! timeout 900 docker build -t "$target_image" "${SCRIPT_DIR_DOCKER}"; then
    safer_back
    die "本地 docker build 失败或超时（900s），请手动检查。"
  fi
  info "本地构建完成：${target_image}"
  safer_back
}

# ============================================================
# compose_up_safe — 启动 stack，带超时和日志收集
# ============================================================
compose_up_safe() {
  local app_dir="$1"
  safer_cd "$app_dir"

  step "启动容器（最多 ${COMPOSE_UP_TIMEOUT}s）..."
  local up_log="/tmp/openppp2-up.log"
  rm -f "$up_log"

  if ! timeout "${COMPOSE_UP_TIMEOUT}" "$COMPOSE_KIND" up -d --remove-orphans 2>&1 | tee "$up_log"; then
    warn "compose up -d 超时或失败，最后 30 行日志："
    tail -n 30 "$up_log" >&2 || true
    safer_back
    die "容器启动失败，请检查上面的日志。"
  fi
  safer_back
}

# ============================================================
# health_check_one <container_name>
# ============================================================
# v2.3 防卡死改动：
#   - 总超时 HEALTH_CHECK_TIMEOUT（默认 40s）
#   - 每秒打印一个点（进度反馈）
#   - 优先看 docker HEALTHCHECK 状态；没有 HEALTHCHECK 则看 Running
#   - 兼容 io_uring 拒绝场景：在日志里抓到就立即 fail
# 返回值：0 健康 / 1 不健康
# ============================================================
health_check_one() {
  local name="$1"
  local timeout_sec="${HEALTH_CHECK_TIMEOUT:-40}"
  local waited=0
  local last_status=""

  info "健康检查容器：${name}（最多 ${timeout_sec}s）"

  while [[ $waited -lt $timeout_sec ]]; do
    # 容器存在性
    if ! docker inspect "$name" >/dev/null 2>&1; then
      sleep 1
      waited=$((waited+1))
      printf "." >&2
      continue
    fi

    # io_uring 致命错误立即 fail
    if docker logs --tail 100 "$name" 2>&1 | grep -q 'io_uring_queue_init: Operation not permitted'; then
      echo
      warn "容器 ${name} 命中 io_uring 拒绝错误（seccomp profile 缺失或未启用）"
      return 1
    fi

    # 优先看 HEALTHCHECK
    local hstat
    hstat="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$name" 2>/dev/null || echo unknown)"
    local running
    running="$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null || echo false)"

    if [[ "$hstat" != "$last_status" ]]; then
      [[ -n "$last_status" ]] && echo
      printf "  [%2ds] running=%s health=%s" "$waited" "$running" "$hstat" >&2
      last_status="$hstat"
    else
      printf "." >&2
    fi

    case "$hstat" in
      healthy)
        echo
        info "容器 ${name} 健康检查通过"
        return 0
        ;;
      unhealthy)
        echo
        warn "容器 ${name} 健康检查失败（unhealthy）"
        docker logs --tail 30 "$name" >&2 2>&1 || true
        return 1
      ;;
      no-healthcheck)
        # 镜像没有 HEALTHCHECK，看 Running + 等够 5s
        if [[ "$running" == "true" && $waited -ge 5 ]]; then
          echo
          info "容器 ${name} 已运行（镜像无 HEALTHCHECK）"
          return 0
        fi
        ;;
    esac

    sleep 1
    waited=$((waited+1))
  done

  echo
  warn "容器 ${name} 健康检查 ${timeout_sec}s 超时（状态：${last_status}）"
  docker logs --tail 30 "$name" >&2 2>&1 || true
  return 1
}

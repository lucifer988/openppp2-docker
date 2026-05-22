#!/usr/bin/env bash
# docker.sh - Docker 管理：安装、Compose 检测、代理、镜像拉取/兜底构建、健康检查

DOCKER_PROXY_DROPIN="/etc/systemd/system/docker.service.d/http-proxy.conf"

# ---------- 安装 Docker / Compose ----------
ensure_docker_stack() {
  local role="${1:-}"
  ensure_pkgs jq curl openssl unzip ca-certificates iproute2
  if ! need_cmd docker; then
    info "未检测到 Docker，开始安装..."
    if need_cmd curl; then
      curl -fsSL https://get.docker.com | sh || die "Docker 安装失败。"
    else
      die "缺少 curl，无法自动安装 Docker。请手动安装后重试。"
    fi
  fi
  if has_systemd; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  detect_compose || die "未检测到 docker compose / docker-compose，请先安装 Compose。"
  info "Docker 就绪（角色：${role:-未知}），Compose：${COMPOSE_KIND}"
}

# 设置 COMPOSE_KIND
detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"; return 0
  elif need_cmd docker-compose; then
    COMPOSE_KIND="docker-compose"; return 0
  fi
  COMPOSE_KIND=""; return 1
}

# compose 封装：始终带上 -f $COMPOSE_FILE，并在 APP_DIR 下执行
# （security_opt 的 seccomp 相对路径按 CLI 的 CWD 解析，必须是 APP_DIR）
compose() {
  case "$COMPOSE_KIND" in
    "docker compose") ( cd "$APP_DIR" && docker compose -f "$COMPOSE_FILE" "$@" ) ;;
    "docker-compose")  ( cd "$APP_DIR" && docker-compose -f "$COMPOSE_FILE" "$@" ) ;;
    *) die "Compose 未检测到，无法执行：$*" ;;
  esac
}

# ---------- 下载基准配置 ----------
download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  local local_copy="${SCRIPT_DIR}/appsettings.base.json"
  if [[ -f "$local_copy" ]]; then
    info "使用脚本目录下的本地基准配置。"
    cp "$local_copy" "${APP_DIR}/appsettings.base.json"
  else
    info "下载基准配置：$url"
    curl_retry -fsSL "$url" -o "${APP_DIR}/appsettings.base.json" \
      || die "基准配置下载失败：$url"
  fi
  # 同时把本地 Dockerfile 复制进 APP_DIR，供兜底构建使用
  [[ -f "${SCRIPT_DIR}/Dockerfile" ]] && cp "${SCRIPT_DIR}/Dockerfile" "${APP_DIR}/Dockerfile" || true
}

# ---------- Docker HTTP 代理 ----------
setup_docker_proxy() {
  local ip="$1" port="$2"
  [[ -n "$ip" && -n "$port" ]] || { warn "代理 IP/端口为空。"; return 1; }
  mkdir -p "$(dirname "$DOCKER_PROXY_DROPIN")"
  cat > "$DOCKER_PROXY_DROPIN" <<EOF
[Service]
Environment="HTTP_PROXY=http://${ip}:${port}"
Environment="HTTPS_PROXY=http://${ip}:${port}"
Environment="NO_PROXY=localhost,127.0.0.1"
EOF
  if has_systemd; then
    systemctl daemon-reload && systemctl restart docker || { warn "重启 Docker 失败。"; return 1; }
  fi
  info "已为 Docker 配置 HTTP 代理 ${ip}:${port}"
  return 0
}

# 拉取后清理代理：删除配置文件但不重启 docker（避免顺手停掉刚起的容器）
cleanup_docker_proxy_after_pull() {
  local configured="${1:-0}"
  [[ "$configured" -eq 1 ]] || return 0
  rm -f "$DOCKER_PROXY_DROPIN" >/dev/null 2>&1 || true
}

# 彻底移除代理（卸载时用，会重启 docker）
remove_docker_proxy() {
  if [[ -f "$DOCKER_PROXY_DROPIN" ]]; then
    rm -f "$DOCKER_PROXY_DROPIN"
    if has_systemd; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl restart docker >/dev/null 2>&1 || true
    fi
  fi
}

# ---------- 镜像：先拉取，失败则本地构建 ----------
ensure_image() {
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    info "镜像已存在于本地：$image"; return 0
  fi
  info "尝试拉取镜像：$image"
  if docker pull "$image" >/dev/null 2>&1; then
    info "拉取成功：$image"; return 0
  fi
  warn "拉取失败：$image"
  warn "（GHCR 包可能未公开发布，或网络不通）将改为在本机用 Dockerfile 构建。"
  build_image_local "$image"
}

build_image_local() {
  local image="$1"
  local df="${APP_DIR}/Dockerfile"
  [[ -f "$df" ]] || df="${SCRIPT_DIR}/Dockerfile"
  if [[ ! -f "$df" ]]; then
    info "本地无 Dockerfile，尝试下载..."
    curl_retry -fsSL "https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/Dockerfile" \
      -o "${APP_DIR}/Dockerfile" || die "无法获取 Dockerfile，本地构建中止。"
    df="${APP_DIR}/Dockerfile"
  fi

  local tag zipurl
  tag="$(curl_retry -fsSL "https://api.github.com/repos/${UPSTREAM_REPO}/releases/latest" 2>/dev/null \
        | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[: ]*"([^"]+)".*/\1/')"
  [[ -n "$tag" ]] || tag="$FALLBACK_UPSTREAM_TAG"

  # 本项目仅支持 amd64（x86_64）
  if [[ "$(uname -m)" != "x86_64" && "$(uname -m)" != "amd64" ]]; then
    die "本项目仅支持 amd64（x86_64）。"
  fi
  zipurl="https://github.com/${UPSTREAM_REPO}/releases/download/${tag}/openppp2-linux-amd64-simd.zip"

  info "本地构建镜像 ${image}（上游 ${tag}）..."
  docker build -t "$image" \
    --build-arg "OPENPPP2_ZIP_URL=${zipurl}" \
    -f "$df" "$(dirname "$df")" \
    || die "本地构建失败，请检查网络能否访问 github.com 下载 release。"
  info "本地构建完成：$image"
}

# ---------- 健康检查（增强版） ----------
# health_check_one <service|container> [role] [probe]
#   role  : server | client
#   probe : server -> 监听端口（默认 20000）
#           client -> "LAN|HTTP_PORT|SOCKS_PORT"，用于真实出网探测
# 返回 0 仅当：容器 Running（且若有 HEALTHCHECK 则为 healthy）+ ppp 进程 + 角色功能探测通过
health_check_one() {
  local name="$1" role="${2:-}" probe="${3:-}"
  local i state health
  local egress_url="https://ifconfig.me"

  # 1) 等待容器 Running
  for ((i=0; i<HEALTH_RETRIES; i++)); do
    state="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)"
    [[ "$state" == "true" ]] && break
    sleep "$HEALTH_INTERVAL"
  done
  if [[ "$state" != "true" ]]; then
    warn "容器未处于运行状态：$name"
    return 1
  fi

  # 2) 若镜像声明了 HEALTHCHECK，等待 healthy
  if docker inspect -f '{{if .State.Health}}yes{{end}}' "$name" 2>/dev/null | grep -q yes; then
    for ((i=0; i<HEALTH_RETRIES; i++)); do
      health="$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo starting)"
      [[ "$health" == "healthy" ]] && break
      [[ "$health" == "unhealthy" ]] && { warn "容器 HEALTHCHECK 为 unhealthy：$name"; return 1; }
      sleep "$HEALTH_INTERVAL"
    done
    [[ "$health" == "healthy" ]] || { warn "容器 HEALTHCHECK 未在限定时间内变 healthy：$name"; return 1; }
  fi

  # 3) ppp 进程是否存在
  if ! docker exec "$name" sh -c 'pgrep -x ppp >/dev/null 2>&1 || pidof ppp >/dev/null 2>&1'; then
    warn "容器内未发现运行中的 ppp 进程：$name"
    return 1
  fi

  # 4) 角色功能探测
  case "$role" in
    server)
      local port="${probe:-20000}"
      # TCP 监听
      if ! docker exec "$name" sh -c "ss -ltn 2>/dev/null | grep -q ':${port}'"; then
        warn "服务端未在端口 ${port} 上监听（TCP）。"
        return 1
      fi
      # UDP 监听（openppp2 server 同时监听 UDP）
      if ! docker exec "$name" sh -c "ss -lun 2>/dev/null | grep -q ':${port}'"; then
        warn "服务端未在端口 ${port} 上监听（UDP）。"
        return 1
      fi
      info "服务端健康检查通过（容器运行 + ppp 进程 + TCP/UDP 监听 ${port}）。"
      ;;
    client)
      # TUN 设备
      if ! docker exec "$name" sh -c 'ip link show 2>/dev/null | grep -q "ppp"'; then
        warn "客户端容器内未发现 TUN 设备（pppN）。"
        return 1
      fi
      # 解析 probe = "LAN|HTTP_PORT|SOCKS_PORT"
      local lan hport sport rest
      lan="${probe%%|*}"; rest="${probe#*|}"
      hport="${rest%%|*}"; sport="${rest#*|}"
      need_cmd curl || { info "客户端健康检查通过（容器运行 + ppp 进程 + TUN；宿主机无 curl，跳过出网探测）。"; return 0; }

      local ok=1
      # HTTP 代理出网探测
      if [[ -n "$lan" && -n "$hport" && "$hport" != "0" ]]; then
        if curl -fsS -x "http://${lan}:${hport}" --max-time 10 -o /dev/null "$egress_url" 2>/dev/null; then
          info "HTTP 代理出网正常：http://${lan}:${hport}"
        else
          warn "HTTP 代理出网探测失败：http://${lan}:${hport}（隧道可能尚未建立，可稍后重试）。"
          ok=0
        fi
      fi
      # SOCKS5 代理出网探测（socks5h：DNS 也走代理）
      if [[ -n "$lan" && -n "$sport" && "$sport" != "0" ]]; then
        if curl -fsS -x "socks5h://${lan}:${sport}" --max-time 10 -o /dev/null "$egress_url" 2>/dev/null; then
          info "SOCKS5 代理出网正常：socks5h://${lan}:${sport}"
        else
          warn "SOCKS5 代理出网探测失败：socks5h://${lan}:${sport}（隧道可能尚未建立，可稍后重试）。"
          ok=0
        fi
      fi
      [[ "$ok" -eq 1 ]] || return 1
      info "客户端健康检查通过（容器运行 + ppp 进程 + TUN + HTTP/SOCKS5 出网）。"
      ;;
    *)
      info "健康检查通过（容器运行 + ppp 进程）：$name"
      ;;
  esac
  return 0
}

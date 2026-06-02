#!/usr/bin/env bash
# docker.sh - Docker 管理：安装、Compose 检测、代理、镜像拉取/兜底构建、健康检查

DOCKER_PROXY_DROPIN="/etc/systemd/system/docker.service.d/http-proxy.conf"

# ---------- 安装 Docker / Compose ----------
ensure_docker_stack() {
  local role="${1:-}"
  ensure_pkgs jq curl openssl unzip ca-certificates iproute2
  if ! need_cmd docker; then
    info "未检测到 Docker，开始安装..."
    install_docker || die "Docker 安装失败：以上所有方式均不可用。请检查网络后手动安装 Docker，再重新运行本脚本。"
  fi
  if has_systemd; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    # 等待 docker 守护进程就绪（最多 ~15s）
    local i
    for ((i = 0; i < 15; i++)); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  need_cmd docker || die "Docker 已安装但无法调用，请检查 docker 服务状态（systemctl status docker）。"
  # 无论是否 systemd，都最终确认 daemon 真的就绪（非 systemd 环境如 WSL/容器可能命令在但 daemon 没起）
  docker info >/dev/null 2>&1 || die "Docker daemon 未就绪。请先启动 Docker（如 systemctl start docker，或对应环境的启动方式）后重试。"
  detect_compose || die "未检测到 docker compose / docker-compose。请安装 Compose 插件后重试（Debian/Ubuntu：apt-get install -y docker-compose-plugin 或 docker-compose-v2）。"
  info "Docker 就绪（角色：${role:-未知}），Compose：${COMPOSE_KIND}"
}

# 多渠道安装 Docker，任一成功即返回 0
install_docker() {
  # 渠道 1：官方便捷脚本（先下载到本地再执行，避免管道中途断流执行残缺脚本）
  if need_cmd curl; then
    local tmp_sh
    tmp_sh="$(mktemp)"
    info "尝试通过官方脚本安装 Docker（get.docker.com）..."
    if curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 https://get.docker.com -o "$tmp_sh" &&
      [[ -s "$tmp_sh" ]] && sh "$tmp_sh"; then
      rm -f "$tmp_sh"
      need_cmd docker && {
        info "Docker 安装成功（官方脚本）。"
        return 0
      }
    fi
    rm -f "$tmp_sh"
    warn "官方脚本安装失败或网络受限，改用发行版软件源..."
  fi

  # 渠道 2：发行版 apt 源（docker.io + compose 插件）。国内网络通常比 get.docker.com 更稳。
  if need_cmd apt-get; then
    info "尝试通过 apt 安装 docker.io 与 compose..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    # 优先装 compose v2 插件；装不上再退回 docker-compose（v1）
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      docker.io docker-compose-v2 >/dev/null 2>&1 ||
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        docker.io docker-compose-plugin >/dev/null 2>&1 ||
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        docker.io docker-compose >/dev/null 2>&1 ||
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        docker.io >/dev/null 2>&1 || true
    if need_cmd docker; then
      info "Docker 安装成功（发行版软件源）。"
      return 0
    fi
    warn "apt 安装 docker.io 失败。"
  fi

  # 渠道 3：dnf / yum（RHEL 系）
  if need_cmd dnf || need_cmd yum; then
    local pm
    pm="$(need_cmd dnf && echo dnf || echo yum)"
    info "尝试通过 ${pm} 安装 docker..."
    "$pm" install -y docker >/dev/null 2>&1 || true
    need_cmd docker && {
      info "Docker 安装成功（${pm}）。"
      return 0
    }
  fi

  return 1
}

# 设置 COMPOSE_KIND
detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"
    return 0
  elif need_cmd docker-compose; then
    COMPOSE_KIND="docker-compose"
    return 0
  fi
  COMPOSE_KIND=""
  return 1
}

# compose 封装：始终带上 -f $COMPOSE_FILE，并在 APP_DIR 下执行
# （security_opt 的 seccomp 相对路径按 CLI 的 CWD 解析，必须是 APP_DIR）
compose() {
  case "$COMPOSE_KIND" in
    "docker compose") (cd "$APP_DIR" && docker compose -f "$COMPOSE_FILE" "$@") ;;
    "docker-compose") (cd "$APP_DIR" && docker-compose -f "$COMPOSE_FILE" "$@") ;;
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
    curl_retry -fsSL "$url" -o "${APP_DIR}/appsettings.base.json" ||
      die "基准配置下载失败：$url"
  fi
  # 同时把本地 Dockerfile 复制进 APP_DIR，供兜底构建使用
  [[ -f "${SCRIPT_DIR}/Dockerfile" ]] && cp "${SCRIPT_DIR}/Dockerfile" "${APP_DIR}/Dockerfile" || true
}

# ---------- Docker HTTP 代理 ----------
setup_docker_proxy() {
  local ip="$1" port="$2"
  [[ -n "$ip" && -n "$port" ]] || {
    warn "代理 IP/端口为空。"
    return 1
  }
  mkdir -p "$(dirname "$DOCKER_PROXY_DROPIN")"
  cat >"$DOCKER_PROXY_DROPIN" <<EOF
[Service]
Environment="HTTP_PROXY=http://${ip}:${port}"
Environment="HTTPS_PROXY=http://${ip}:${port}"
Environment="NO_PROXY=localhost,127.0.0.1"
EOF
  if has_systemd; then
    systemctl daemon-reload && systemctl restart docker || {
      warn "重启 Docker 失败。"
      return 1
    }
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
    info "镜像已存在于本地：$image"
    return 0
  fi
  info "尝试拉取镜像：$image"
  if docker pull "$image" >/dev/null 2>&1; then
    info "拉取成功：$image"
    return 0
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
    info "本地无 Dockerfile，尝试下载（固定 tag ${REPO_REF}）..."
    curl_retry -fsSL "${REPO_RAW_BASE}/Dockerfile" \
      -o "${APP_DIR}/Dockerfile" || die "无法获取 Dockerfile，本地构建中止。"
    df="${APP_DIR}/Dockerfile"
  fi

  local tag zipurl zipsha=""
  # 用 jq 解析（jq 是本项目硬依赖）。注意 set -euo pipefail：命令替换里的管道一旦非 0
  # 会触发 set -e 直接退出，走不到下面的"回退固定版本"。故显式 || true 兜底，确保失败时
  # tag 为空字符串、继续往下走回退逻辑。
  tag="$(
    curl_retry -fsSL "https://api.github.com/repos/${UPSTREAM_REPO}/releases/latest" 2>/dev/null |
      jq -r '.tag_name // empty' 2>/dev/null || true
  )"
  # 上游版本形如 1.0.0.26151；查询失败或格式异常（API 限流/字段改名）一律回退固定版本，
  # 避免把畸形的 tag 拼进下载 URL 导致后续静默 404。
  if [[ ! "$tag" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
    warn "未能可靠解析上游最新版本（得到：'${tag:-空}'），回退固定版本 ${FALLBACK_UPSTREAM_TAG}。"
    tag="$FALLBACK_UPSTREAM_TAG"
  fi
  # 仅当构建用的是我们内置了 SHA256 的固定版本时才校验完整性；
  # 若用的是动态查询到的"最新版"，其 sha 未知，留空让 Dockerfile 跳过校验并告警。
  if [[ "$tag" == "$FALLBACK_UPSTREAM_TAG" ]]; then
    zipsha="$FALLBACK_UPSTREAM_SHA256"
  else
    warn "本地构建使用上游最新版 ${tag}，其 zip SHA256 未知，将跳过完整性校验。"
  fi

  # 本项目仅支持 amd64（x86_64）
  if [[ "$(uname -m)" != "x86_64" && "$(uname -m)" != "amd64" ]]; then
    die "本项目仅支持 amd64（x86_64）。"
  fi
  zipurl="https://github.com/${UPSTREAM_REPO}/releases/download/${tag}/openppp2-linux-amd64-simd.zip"

  info "本地构建镜像 ${image}（上游 ${tag}）..."
  docker build -t "$image" \
    --build-arg "OPENPPP2_ZIP_URL=${zipurl}" \
    --build-arg "OPENPPP2_ZIP_SHA256=${zipsha}" \
    -f "$df" "$(dirname "$df")" ||
    die "本地构建失败，请检查网络能否访问 github.com 下载 release。"
  info "本地构建完成：$image"
}

# ---------- 镜像固定到不可变 digest（可复现） ----------
# resolve_image_digest <ref> -> 打印 repo@sha256:...（解析失败返回非 0）
#   优先用本地已拉取镜像的 RepoDigests；本地构建的镜像没有 RepoDigests（未关联 registry），
#   会解析失败，此时调用方应回退使用原 ref（浮动标签），仅牺牲"可复现"，不影响可用性。
resolve_image_digest() {
  local ref="$1" dg
  dg="$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null |
    grep -m1 '@sha256:' || true)"
  [[ -n "$dg" ]] && {
    echo "$dg"
    return 0
  }
  return 1
}

# pin_compose_to_digest <channel_ref>
#   - 记录浮动通道（.image_channel）供后续自动更新发现新版；
#   - 把 compose 里所有 service 的 image 行替换为不可变 digest 引用（boot/轮转重建不再漂移）；
#   - 同步写入 .image（客户端多实例渲染会读取它）。
#   解析不到 digest（如本地构建镜像）时，保留浮动标签并告警，不阻断安装。
pin_compose_to_digest() {
  local channel="$1" pinned
  echo "$channel" >"${APP_DIR}/.image_channel"
  chmod 600 "${APP_DIR}/.image_channel" 2>/dev/null || true
  if pinned="$(resolve_image_digest "$channel")"; then
    sed -i -E "s|^([[:space:]]*image:[[:space:]]*).*|\1${pinned}|" "$COMPOSE_FILE"
    echo "$pinned" >"$(_image_file)"
    info "已将运行镜像固定到不可变 digest：${pinned}"
  else
    warn "无法解析镜像 digest（可能是本机构建镜像），compose 仍使用浮动标签：${channel}（可复现性下降，不影响运行）。"
  fi
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
  for ((i = 0; i < HEALTH_RETRIES; i++)); do
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
    for ((i = 0; i < HEALTH_RETRIES; i++)); do
      health="$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo starting)"
      [[ "$health" == "healthy" ]] && break
      [[ "$health" == "unhealthy" ]] && {
        warn "容器 HEALTHCHECK 为 unhealthy：$name"
        return 1
      }
      sleep "$HEALTH_INTERVAL"
    done
    [[ "$health" == "healthy" ]] || {
      warn "容器 HEALTHCHECK 未在限定时间内变 healthy：$name"
      return 1
    }
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
      # 解析 probe = "LAN|HTTP_PORT|SOCKS_PORT[|SOCKS_USER|SOCKS_PASS]"
      # 末两段为 SOCKS5 认证（openppp2 客户端会给 socks-proxy 设随机用户名/密码）；
      # 缺省（旧调用方只传 3 段）则按无认证探测，保持向后兼容。
      local lan hport sport suser spass
      local -a _pf=()
      IFS='|' read -r -a _pf <<<"$probe"
      lan="${_pf[0]:-}"
      hport="${_pf[1]:-}"
      sport="${_pf[2]:-}"
      suser="${_pf[3]:-}"
      spass="${_pf[4]:-}"
      need_cmd curl || {
        info "客户端健康检查通过（容器运行 + ppp 进程 + TUN；宿主机无 curl，跳过出网探测）。"
        return 0
      }

      local ok=1
      # HTTP 代理出网探测（openppp2 的 http-proxy 无认证字段，故不带凭据）
      if [[ -n "$lan" && -n "$hport" && "$hport" != "0" ]]; then
        if curl -fsS -x "http://${lan}:${hport}" --max-time 10 -o /dev/null "$egress_url" 2>/dev/null; then
          info "HTTP 代理出网正常：http://${lan}:${hport}"
        else
          warn "HTTP 代理出网探测失败：http://${lan}:${hport}（隧道可能尚未建立，可稍后重试）。"
          ok=0
        fi
      fi
      # SOCKS5 代理出网探测（socks5h：DNS 也走代理）；若配置了用户名/密码则带上认证，
      # 否则 openppp2 要求认证时探测会 407 误判不健康，进而在自动更新里误触发回滚。
      if [[ -n "$lan" && -n "$sport" && "$sport" != "0" ]]; then
        local -a sauth=()
        [[ -n "$suser" ]] && sauth=(--proxy-user "${suser}:${spass}")
        if curl -fsS "${sauth[@]}" -x "socks5h://${lan}:${sport}" --max-time 10 -o /dev/null "$egress_url" 2>/dev/null; then
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

#!/usr/bin/env bash
# install_openppp2.sh — openppp2 Docker 一键部署主入口
# 模块化版本：所有功能函数已拆分至 lib/ 目录。
# 若只下载/管道运行了本文件（缺少 lib/），脚本会自动下载完整项目并重新执行。
set -euo pipefail

# 收紧默认权限：本脚本会写入含密钥的配置文件（appsettings*.json）、凭据、compose 等，
# umask 077 确保新建文件默认 600、目录 700，避免世界可读。各处仍会显式 chmod 兜底。
umask 077

# 本仓库固定下载基准（tag）。自举阶段早于 source config.sh，故这里也要有一份默认值，
# 必须与 config.sh 中的 REPO_REF 保持一致。可用 OPENPPP2_REF 覆盖。
OPENPPP2_REF="${OPENPPP2_REF:-v2.3.0}"

# 完整项目 tar 包地址：锚定到固定 tag（不再默认 main 分支），保证可复现。
# 可用环境变量 OPENPPP2_REPO_TARBALL 覆盖到镜像源。
OPENPPP2_REPO_TARBALL="${OPENPPP2_REPO_TARBALL:-https://github.com/lucifer988/openppp2-docker/archive/refs/tags/${OPENPPP2_REF}.tar.gz}"

# 解析自身所在目录（管道运行时可能拿不到，故容错）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "$PWD")"

# === 自举：缺少模块时自动拉取完整项目并重新执行 ===
_bootstrap_if_needed() {
  [[ "${OPENPPP2_BOOTSTRAPPED:-0}" == "1" ]] && return 0
  [[ -f "${SCRIPT_DIR}/lib/core.sh" && -f "${SCRIPT_DIR}/config.sh" ]] && return 0

  echo "[INFO] 未检测到模块文件，正在下载完整项目..."
  command -v curl >/dev/null 2>&1 || {
    echo "[ERROR] 需要 curl，请先安装。" >&2
    exit 1
  }
  command -v tar >/dev/null 2>&1 || {
    echo "[ERROR] 需要 tar，请先安装。" >&2
    exit 1
  }

  local tmp dir
  tmp="$(mktemp -d)"
  if ! curl -fsSL "$OPENPPP2_REPO_TARBALL" -o "${tmp}/repo.tar.gz"; then
    echo "[ERROR] 下载完整项目失败：${OPENPPP2_REPO_TARBALL}" >&2
    echo "        可设置 OPENPPP2_REPO_TARBALL 指向镜像源后重试。" >&2
    exit 1
  fi
  tar -xzf "${tmp}/repo.tar.gz" -C "$tmp" || {
    echo "[ERROR] 解压失败。" >&2
    exit 1
  }
  dir="$(find "$tmp" -maxdepth 1 -mindepth 1 -type d -name 'openppp2-docker*' | head -n1)"
  [[ -n "$dir" && -f "${dir}/install_openppp2.sh" && -f "${dir}/lib/core.sh" ]] ||
    {
      echo "[ERROR] 项目结构异常，无法继续。" >&2
      exit 1
    }
  chmod +x "${dir}/install_openppp2.sh"
  echo "[INFO] 已获取完整项目，开始执行安装..."
  OPENPPP2_BOOTSTRAPPED=1 exec bash "${dir}/install_openppp2.sh" "$@"
}
_bootstrap_if_needed "$@"

# 重新执行后（或本就是完整项目）此处 SCRIPT_DIR 必定包含 lib/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# === 加载配置与模块库 ===
source "${SCRIPT_DIR}/config.sh"

# 按依赖顺序加载 lib 模块
source "${SCRIPT_DIR}/lib/core.sh"
source "${SCRIPT_DIR}/lib/network.sh"
source "${SCRIPT_DIR}/lib/seccomp.sh"
source "${SCRIPT_DIR}/lib/docker.sh"
source "${SCRIPT_DIR}/lib/compose.sh"
source "${SCRIPT_DIR}/lib/systemd.sh"
source "${SCRIPT_DIR}/lib/backup.sh"
source "${SCRIPT_DIR}/lib/client.sh"

# ============================================================
#  主安装逻辑（编排层，调用各模块函数）
# ============================================================
do_install() {
  echo "=============================="
  echo "  请选择安装/部署角色："
  echo "    1) 服务端（Server）"
  echo "    2) 客户端（Client）"
  echo "=============================="
  local ROLE
  prompt ROLE "请输入数字选择（1 或 2）" "1"

  case "$ROLE" in
    1) ensure_docker_stack "server" ;;
    2) ensure_docker_stack "client" ;;
    *) die "角色选择错误，只能输入 1 或 2。" ;;
  esac

  local IMAGE BASE_URL
  prompt IMAGE "请输入镜像地址" "${DEFAULT_IMAGE}"
  prompt BASE_URL "请输入基准配置文件 URL（appsettings.base.json 的 raw 链接）" "${DEFAULT_BASE_CFG_URL}"

  download_base_cfg "$BASE_URL"
  cd "$APP_DIR"

  generate_seccomp_profile "$SECCOMP_FILE"

  local proxy_configured=0
  local proxy_cleanup_deferred=0

  if [[ "$ROLE" == "1" ]]; then
    # ============ 服务端 ============
    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的服务端配置文件名称（例如 appsettings.json）" "appsettings.json"

    local SERVER_PUBLIC_IP autoip=""
    autoip="$(curl_retry -sS https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$autoip" ]]; then
      prompt SERVER_PUBLIC_IP "请输入服务端对外（公网）IP 地址" "$autoip"
    else
      prompt SERVER_PUBLIC_IP "请输入服务端对外（公网）IP 地址" ""
    fi

    local SERVER_BIND_IP
    prompt SERVER_BIND_IP "请输入服务端监听（bind）IP 地址（NAT/云主机通常填内网 IP，直连填公网 IP）" "${SERVER_PUBLIC_IP}"

    # ★ 安全修复：随机生成共享密钥（kf / protocol-key / transport-key）
    local KF PK TK
    KF="$(gen_int)"
    PK="$(gen_secret 24)"
    TK="$(gen_secret 32)"

    jq --arg ip "$SERVER_PUBLIC_IP" \
      --arg bind "$SERVER_BIND_IP" \
      --argjson kf "$KF" \
      --arg pk "$PK" \
      --arg tk "$TK" \
      '.ip.public=$ip | .ip.interface=$bind
        | .key.kf=$kf | .key["protocol-key"]=$pk | .key["transport-key"]=$tk' \
      appsettings.base.json >"$APP_CFG_NAME"
    chmod 600 "$APP_CFG_NAME" 2>/dev/null || true # 含 protocol-key/transport-key，禁止世界可读

    write_compose_server "$IMAGE" "$APP_CFG_NAME"
    echo "server" >"${APP_DIR}/.role"

    # 写入并打印凭据（客户端需要用到，必须严格一致）
    {
      echo "# openppp2 服务端凭据（生成时间：$(date '+%F %T')）"
      echo "# 客户端安装时需粘贴以下三项，必须与本服务端完全一致。"
      echo "kf=${KF}"
      echo "protocol-key=${PK}"
      echo "transport-key=${TK}"
      echo "# 算法（如客户端默认值不同，请一并对齐）"
      echo "protocol=simd-aes-128-cfb"
      echo "transport=simd-aes-256-cfb"
    } >"$CREDENTIALS_FILE"
    chmod 600 "$CREDENTIALS_FILE" 2>/dev/null || true

    echo
    echo "★★★ 请记录以下服务端密钥（客户端部署时需要，且不要泄露） ★★★"
    echo "  kf            ：${KF}"
    echo "  protocol-key  ：${PK}"
    echo "  transport-key ：${TK}"
    echo "  已保存到       ：${CREDENTIALS_FILE}"
    echo

  elif [[ "$ROLE" == "2" ]]; then
    # ============ 客户端 ============
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：宿主机不支持 TUN，client 无法运行。"

    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的客户端配置文件名称（例如 appsettings.json）" "appsettings.json"

    local MAIN_SERVICE_NAME
    prompt MAIN_SERVICE_NAME "请输入主客户端实例名称（容器/服务名）" "openppp2"

    local SERVER_IP SERVER_PORT guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端 IP（例如 1.2.3.4）" ""
    prompt_port SERVER_PORT "请输入服务端端口（例如 20000）" "20000"

    # ★ 安全修复：客户端必须粘贴服务端的共享密钥（不能各自随机，否则握手失败）
    local KF PK TK
    echo
    info "请粘贴服务端的密钥（来自服务端 ${CREDENTIALS_FILE}，必须完全一致）。"
    prompt KF "请输入 key.kf（数值）" ""
    prompt PK "请输入 protocol-key" ""
    prompt TK "请输入 transport-key" ""
    [[ -n "$PK" && -n "$TK" ]] || die "protocol-key / transport-key 不能为空，否则无法与服务端互通。"
    [[ "$KF" =~ ^[0-9]+$ ]] || {
      warn "kf 非数值，按 0 处理（若服务端 kf 非 0，将无法连通）。"
      KF=0
    }

    guid="$(gen_guid)"
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"
    netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"
    gw="${netinfo#*|}"

    if [[ -z "${lan:-}" || "${lan:-}" =~ ^10\. ]]; then
      warn "自动检测到的 LAN IP 为空或为 10.x（可能是隧道），请手动输入正确的内网 IP。"
      prompt lan "请输入客户端内网 IP（用于 http/socks bind，例如 192.168.1.100）" ""
    else
      info "检测到客户端内网 IP：${lan}"
    fi

    if [[ -z "${nic:-}" ]]; then
      warn "未能自动检测默认网卡名（dev），请手动输入。"
      prompt nic "请输入默认网卡名（例如 eth0、ens3、ens192）" "$DEFAULT_CLIENT_NIC"
    else
      info "检测到默认网卡：${nic}"
    fi

    if [[ -z "${gw:-}" ]]; then
      warn "未能自动检测默认网关（via），请手动输入。"
      prompt gw "请输入默认网关（例如 192.168.1.1）" ""
    else
      info "检测到默认网关：${gw}"
    fi
    [[ -n "${gw:-}" ]] || die "网关地址不能为空。客户端必须指定网关才能正确路由流量。"

    local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

    # 端口与本地 SOCKS 凭据（随机化）
    local HTTP_PORT SOCKS_PORT S_USER S_PASS
    HTTP_PORT="$(random_free_port)"
    SOCKS_PORT="$(random_free_port)"
    while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do SOCKS_PORT="$(random_free_port)"; done
    S_USER="user_$(gen_secret 8)"
    S_PASS="$(gen_password 20)"

    jq --argjson kf "$KF" --arg pk "$PK" --arg tk "$TK" \
      --arg srv "$SERVER_URI" --arg guid "$guid" --arg lan "$lan" \
      --argjson hport "$HTTP_PORT" --argjson sport "$SOCKS_PORT" \
      --arg suser "$S_USER" --arg spass "$S_PASS" \
      '.key.kf=$kf | .key["protocol-key"]=$pk | .key["transport-key"]=$tk
        | .client.server=$srv | .client.guid=$guid
        | .client["http-proxy"].bind=$lan  | .client["http-proxy"].port=$hport
        | .client["socks-proxy"].bind=$lan | .client["socks-proxy"].port=$sport
        | .client["socks-proxy"].username=$suser | .client["socks-proxy"].password=$spass' \
      appsettings.base.json >"$APP_CFG_NAME"
    chmod 600 "$APP_CFG_NAME" 2>/dev/null || true # 含密钥与 SOCKS5 凭据，禁止世界可读

    enable_ip_forward_host

    local tun_name="ppp0"
    local tun_ip="10.0.0.2"
    local tun_gw="10.0.0.1"

    local USE_MUX
    prompt USE_MUX "是否开启 mux？(yes/no)" "no"
    write_compose_client "$IMAGE" "$nic" "$gw" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME" "$tun_name" "$tun_ip" "$tun_gw" "$USE_MUX"

    echo "client" >"${APP_DIR}/.role"
    echo "$MAIN_SERVICE_NAME" >"${APP_DIR}/.client_main_service"

    echo
    echo "当前客户端配置信息："
    echo "  配置文件 ：${APP_CFG_NAME}"
    echo "  server   ：${SERVER_URI}"
    echo "  SOCKS5   ：${lan}:${SOCKS_PORT}  用户名 ${S_USER}  密码 ${S_PASS}"
    echo "  HTTP     ：${lan}:${HTTP_PORT}"

    echo
    local USE_PROXY
    prompt USE_PROXY "是否需要为 Docker 配置 HTTP 代理来拉取镜像？（yes/no）" "no"

    if [[ "$USE_PROXY" == "yes" ]]; then
      local PROXY_IP PROXY_PORT
      prompt PROXY_IP "请输入代理服务器 IP 地址" ""
      prompt_port PROXY_PORT "请输入代理服务器端口" "7890"
      if setup_docker_proxy "$PROXY_IP" "$PROXY_PORT"; then
        proxy_configured=1
      else
        warn "代理配置失败，将不使用代理继续安装。"
      fi
    fi
  else
    die "角色选择错误，只能输入 1 或 2。"
  fi

  # ★ 镜像修复（issue #1）：先拉取，失败则用 Dockerfile 本地构建
  echo
  info "准备镜像（拉取失败将自动本地构建）..."
  ensure_image "$IMAGE"

  if [[ "$ROLE" == "2" ]]; then
    cleanup_docker_proxy_after_pull "$proxy_configured"
    if [[ "$proxy_configured" -eq 1 ]]; then
      proxy_cleanup_deferred=1
      info "已完成镜像准备，Docker 代理将在本次安装结束后保留为未生效状态（配置文件已删，未重启 daemon）。"
    fi
  fi

  echo
  info "启动 openppp2..."
  cd "$APP_DIR"
  compose up -d --remove-orphans

  # ★ 健康检查修复（issue #4）：传入角色与功能探测目标
  if [[ "$ROLE" == "2" ]]; then
    local main_svc
    main_svc="$(cat "${APP_DIR}/.client_main_service" 2>/dev/null || echo openppp2)"
    health_check_one "$main_svc" "client" "${lan}|${HTTP_PORT}|${SOCKS_PORT}" ||
      warn "健康检查未通过，请手动检查容器状态（docker logs ${main_svc}）。"
  else
    health_check_one "openppp2" "server" "${SERVER_PORT:-20000}" ||
      warn "健康检查未通过，请手动检查容器状态（docker logs openppp2）。"
  fi

  setup_systemd_weekly_update

  if [[ "$ROLE" == "2" && "$proxy_cleanup_deferred" -eq 1 ]]; then
    echo
    warn "注意：Docker 代理配置文件已删除，但当前 Docker daemon 尚未重启。"
    warn "这样做是为了避免刚启动的 openppp2 容器被 Docker 重启顺手停掉。"
    warn "如果你后续确实要让 Docker 立即丢弃旧代理，请手动执行：systemctl restart docker"
    warn "执行后 openppp2 会因 restart: unless-stopped 自动拉起。"
  fi

  echo
  echo "===== 完成 ====="
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f <服务名>"
  echo
  info "安全配置：seccomp 采用 Docker 默认 allowlist 基线（默认拒绝）+ 仅放行 io_uring。"
  info "密钥已随机化：protocol-key / transport-key / SOCKS5 凭据均为本次部署独立生成。"
}

do_uninstall() {
  info "开始卸载 openppp2（不卸载 Docker）..."

  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
    systemctl disable --now openppp2-logrotate.timer >/dev/null 2>&1 || true
    systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
    /etc/systemd/system/openppp2-update.service \
    /usr/local/bin/openppp2-update.sh \
    /etc/systemd/system/openppp2-logrotate.timer \
    /etc/systemd/system/openppp2-logrotate.service \
    /usr/local/bin/openppp2-logrotate.sh \
    /etc/systemd/system/openppp2-boot.service \
    /usr/local/bin/openppp2-wait-uptime.sh \
    /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  if need_cmd docker; then
    local containers
    containers="$(docker ps -a --filter name=openppp2 --format '{{.Names}}' 2>/dev/null || true)"
    if [[ -n "$containers" ]]; then
      info "停止并删除 openppp2 容器..."
      for c in $containers; do
        docker rm -f "$c" >/dev/null 2>&1 || true
      done
    fi
  fi

  if [[ -d "$APP_DIR" ]] && need_cmd docker; then
    cd "$APP_DIR"
    detect_compose >/dev/null 2>&1 || true
    if [[ -n "$COMPOSE_KIND" ]]; then
      info "停止并清理 compose 资源..."
      compose down --remove-orphans >/dev/null 2>&1 || true
    fi
  fi

  local KEEP_BACKUP
  prompt KEEP_BACKUP "是否保留备份文件（backups 目录）？(yes/no)" "yes"

  if [[ "$KEEP_BACKUP" == "yes" ]]; then
    local tmp_backup=""
    if [[ -d "$BACKUP_DIR" ]]; then
      tmp_backup="/tmp/openppp2-backups-$(date +%Y%m%d_%H%M%S)"
      mv "$BACKUP_DIR" "$tmp_backup" >/dev/null 2>&1 || true
    fi

    if need_cmd docker; then
      local running
      running="$(docker ps --filter name=openppp2 --format '{{.Names}}' 2>/dev/null || true)"
      if [[ -n "$running" ]]; then
        warn "以下容器仍在运行，请手动停止后再卸载：$running"
        die "卸载中止：仍有运行中的 openppp2 容器。"
      fi
    fi

    info "删除目录 ${APP_DIR} ..."
    rm -rf "$APP_DIR"

    if [[ -n "$tmp_backup" && -d "$tmp_backup" ]]; then
      mkdir -p "$APP_DIR"
      mv "$tmp_backup" "$BACKUP_DIR" >/dev/null 2>&1 || true
    fi
  else
    info "删除目录 ${APP_DIR} ..."
    rm -rf "$APP_DIR"
  fi

  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  remove_docker_proxy

  echo "卸载完成。"
}

# ============================================================
#  菜单入口
# ============================================================
main() {
  check_env_supported

  echo "=============================="
  echo "  openppp2 一键部署脚本 v${SCRIPT_VERSION}"
  echo "=============================="
  echo "请选择操作："
  echo "  1) 安装 openppp2"
  echo "  2) 卸载 openppp2"
  echo "  3) 新增 openppp2 客户端实例"
  echo "  4) 查看客户端配置和代理信息"
  echo "  5) 删除客户端实例/配置（避免重启反复拉起）"
  echo "  6) 备份当前配置文件"
  echo "  7) 回滚（恢复最新备份）"
  echo "=============================="

  local ACTION
  prompt ACTION "请输入数字选择（1 / 2 / 3 / 4 / 5 / 6 / 7）" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_add_client ;;
    4) do_show_info ;;
    5) do_delete_client ;;
    6) do_backup ;;
    7) do_restore ;;
    *) die "输入错误，只能是 1 / 2 / 3 / 4 / 5 / 6 / 7。" ;;
  esac
}

main "$@"

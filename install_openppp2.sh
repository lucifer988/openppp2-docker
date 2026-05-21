#!/usr/bin/env bash
# install_openppp2.sh — openppp2 Docker 一键部署主入口
# 模块化重构版本：所有功能函数已拆分至 lib/ 目录
#
# v2.2 改动（详见 README "更新日志"）：
#   * Dockerfile  : 增加 SHA256 校验 / 非 root 用户 / tini / HEALTHCHECK
#   * compose.sh  : cap_drop ALL + no-new-privileges + 资源限制 + 日志轮转
#   * systemd.sh  : 自动更新带健康检查 + 失败回滚 + 可选 webhook 通知
#   * config.sh   : OPENPPP2_IMAGE_REPO / OPENPPP2_IMAGE_TAG 分离，便于固定版本
#   * core.sh     : safer_cd/safer_back 安全切换目录工具
set -euo pipefail

# ============================================================
#  Standalone bootstrap
# ============================================================
# 支持以下两种安装方式：
#   1) 克隆完整仓库后运行：sudo ./install_openppp2.sh
#   2) 只下载本文件运行，或 curl ... | sudo bash
#
# 第 2 种情况下，当前目录没有 config.sh / lib/*.sh；脚本会自动拉取
# GitHub main 分支的完整项目临时副本，然后切换到完整副本继续执行。
REPO_OWNER="${OPENPPP2_REPO_OWNER:-lucifer988}"
REPO_NAME="${OPENPPP2_REPO_NAME:-openppp2-docker}"
REPO_BRANCH="${OPENPPP2_REPO_BRANCH:-main}"
REPO_ARCHIVE_URL="${OPENPPP2_REPO_ARCHIVE_URL:-https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz}"

resolve_script_dir() {
  local src="${BASH_SOURCE[0]:-$0}"
  if [[ -n "$src" && "$src" != "bash" && "$src" != "-" ]]; then
    cd "$(dirname "$src")" 2>/dev/null && pwd -P && return 0
  fi
  pwd -P
}

SCRIPT_DIR="$(resolve_script_dir)"

bootstrap_full_project_if_needed() {
  local required=(
    "config.sh"
    "appsettings.base.json"
    "lib/core.sh"
    "lib/network.sh"
    "lib/seccomp.sh"
    "lib/docker.sh"
    "lib/compose.sh"
    "lib/systemd.sh"
    "lib/backup.sh"
    "lib/client.sh"
  )

  local rel missing=0
  for rel in "${required[@]}"; do
    if [[ ! -f "${SCRIPT_DIR}/${rel}" ]]; then
      missing=1
      break
    fi
  done

  [[ "$missing" -eq 0 ]] && return 0

  if [[ "${OPENPPP2_BOOTSTRAPPED:-0}" == "1" ]]; then
    echo "[!] 已尝试拉取完整项目，但仍缺少必要文件。请检查仓库内容或网络连接。" >&2
    echo "[!] 当前目录：${SCRIPT_DIR}" >&2
    exit 1
  fi

  command -v curl >/dev/null 2>&1 || {
    echo "[!] 缺少 curl，无法自动拉取完整项目。请先安装 curl。" >&2
    exit 1
  }
  command -v tar >/dev/null 2>&1 || {
    echo "[!] 缺少 tar，无法解压 GitHub 项目归档。请先安装 tar。" >&2
    exit 1
  }

  local tmp_dir repo_dir
  tmp_dir="$(mktemp -d /tmp/openppp2-docker.XXXXXX)"

  echo "[*] 检测到当前只运行了入口脚本，正在自动拉取完整项目文件..."
  echo "[*] 来源：${REPO_ARCHIVE_URL}"

  if ! curl -fsSL --retry 5 --retry-delay 2 --connect-timeout 10 --max-time 180 \
      "${REPO_ARCHIVE_URL}" | tar -xz -C "${tmp_dir}"; then
    echo "[!] 拉取或解压完整项目失败。" >&2
    echo "[!] 你也可以手动执行：git clone https://github.com/${REPO_OWNER}/${REPO_NAME}.git && cd ${REPO_NAME} && sudo ./install_openppp2.sh" >&2
    exit 1
  fi

  repo_dir="${tmp_dir}/${REPO_NAME}-${REPO_BRANCH}"
  if [[ ! -d "$repo_dir" ]]; then
    repo_dir="$(find "${tmp_dir}" -mindepth 1 -maxdepth 1 -type d -name "${REPO_NAME}-*" | head -n 1 || true)"
  fi

  if [[ -z "${repo_dir:-}" || ! -f "${repo_dir}/install_openppp2.sh" ]]; then
    echo "[!] GitHub 归档中没有找到 install_openppp2.sh。" >&2
    exit 1
  fi

  chmod +x "${repo_dir}/install_openppp2.sh" >/dev/null 2>&1 || true
  export OPENPPP2_BOOTSTRAPPED=1
  exec bash "${repo_dir}/install_openppp2.sh" "$@"
}

bootstrap_full_project_if_needed "$@"

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
  cd "$APP_DIR" || die "无法进入应用目录：$APP_DIR"

  generate_seccomp_profile "$SECCOMP_FILE"

  local proxy_configured=0
  local proxy_cleanup_deferred=0

  if [[ "$ROLE" == "1" ]]; then
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

    jq --arg ip "$SERVER_PUBLIC_IP" \
       --arg bind "$SERVER_BIND_IP" \
       '.ip.public=$ip | .ip.interface=$bind' \
       appsettings.base.json > "$APP_CFG_NAME"

    write_compose_server "$IMAGE" "$APP_CFG_NAME"
    echo "server" > "${APP_DIR}/.role"

  elif [[ "$ROLE" == "2" ]]; then
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：宿主机不支持 TUN，client 无法运行。"

    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的客户端配置文件名称（例如 appsettings-RFCHK.json）" "appsettings.json"


    local MAIN_SERVICE_NAME
    prompt MAIN_SERVICE_NAME "请输入主客户端实例名称（容器/服务名）" "openppp2"

    local SERVER_IP SERVER_PORT guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端 IP（例如 1.2.3.4）" ""
    prompt_port SERVER_PORT "请输入服务端端口（例如 20000）" "20000"

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
      prompt nic "请输入默认网卡名（例如 eth0、ens3、ens192）" ""
    else
      info "检测到默认网卡：${nic}"
    fi

    if [[ -z "${gw:-}" ]]; then
      warn "未能自动检测默认网关（via），请手动输入。"
      prompt gw "请输入默认网关（例如 192.168.1.1）" ""
    else
      info "检测到默认网关：${gw}"
    fi

    if [[ -z "${gw:-}" ]]; then
      die "网关地址不能为空。客户端必须指定网关才能正确路由流量。"
    fi

    local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

    local HTTP_PORT SOCKS_PORT
    HTTP_PORT="$(random_free_port)"
    SOCKS_PORT="$(random_free_port)"
    while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do
      SOCKS_PORT="$(random_free_port)"
    done

    jq --arg srv "$SERVER_URI" \
       --arg guid "$guid" \
       --arg lan "$lan" \
       --argjson hport "$HTTP_PORT" \
       --argjson sport "$SOCKS_PORT" \
       '.client.server=$srv | .client.guid=$guid | .client["http-proxy"].bind=$lan | .client["socks-proxy"].bind=$lan | .client["http-proxy"].port=$hport | .client["socks-proxy"].port=$sport' \
       appsettings.base.json > "$APP_CFG_NAME"

    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    enable_ip_forward_host

    local tun_name="ppp0"
    local tun_ip="10.0.0.2"
    local tun_gw="10.0.0.1"

    local USE_MUX
    unset USE_MUX
    prompt USE_MUX "是否开启 mux？(yes/no)" "no"
    write_compose_client "$IMAGE" "$nic" "$gw" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME" "$tun_name" "$tun_ip" "$tun_gw" "$USE_MUX"

    echo "client" > "${APP_DIR}/.role"
    echo "$MAIN_SERVICE_NAME" > "${APP_DIR}/.client_main_service"

    echo
    echo "当前客户端配置信息："
    echo "  配置文件：${APP_CFG_NAME}"
    echo "  server   ：${SERVER_URI}"
    echo "  SOCKS5   ：${lan}:${SOCKS_PORT}"
    echo "  HTTP     ：${lan}:${HTTP_PORT}"
    echo "  tun-host ：no（已强制写入命令行参数）"

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

  echo
  info "预拉取镜像..."
  cd "$APP_DIR" || die "无法进入应用目录：$APP_DIR"
  compose pull || true

  if [[ "$ROLE" == "2" ]]; then
    # ============================================================
    # 「延后回收 Docker 代理」机制：
    # 客户端在第一次安装时可能临时配置了 Docker daemon 的 HTTP proxy
    # 来加速 ghcr.io 镜像拉取。但是 `systemctl restart docker` 会
    # 顺手把刚启动的容器全部停一遍——如果我们这里立刻 restart 一次去
    # 应用「无代理」状态，那么 compose up -d 启动的 openppp2 容器
    # 会被刚 pull 完代理就拆掉的 daemon 重启给打断。
    #
    # 折中方案：把 /etc/systemd/system/docker.service.d/http-proxy.conf
    # 删除（这样开机或下次 daemon-reload 时就不再带代理），但本次安装
    # 不重启 docker daemon。安装结束后给用户明确提示，让其在合适窗口
    # 自己手动 `systemctl restart docker`。
    # cleanup_docker_proxy_after_pull 内部实现了「只删文件、不重启」。
    # ============================================================
    cleanup_docker_proxy_after_pull "$proxy_configured"
    if [[ "$proxy_configured" -eq 1 ]]; then
      proxy_cleanup_deferred=1
      info "已完成镜像拉取，Docker 代理将在本次安装结束后保留为未生效状态（配置文件已删，未重启 daemon）。"
    fi
  fi

  echo
  info "启动 openppp2..."
  compose up -d --remove-orphans

  if [[ "$ROLE" == "2" ]]; then
    health_check_one "$(cat "${APP_DIR}/.client_main_service" 2>/dev/null || echo openppp2)" || warn "健康检查未通过，请手动检查容器状态"
  else
    health_check_one "openppp2" || warn "健康检查未通过，请手动检查容器状态"
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
  info "安全配置：使用自定义 seccomp 配置（仅放开必要的 io_uring 系统调用）"
}


do_uninstall() {
  info "开始卸载 openppp2（不卸载 Docker）..."

  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
    systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh \
        /etc/systemd/system/openppp2-boot.service \
        /usr/local/bin/openppp2-wait-uptime.sh \
        /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  if need_cmd docker; then
    # 清理所有 openppp2 容器（包括多实例）
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
    cd "$APP_DIR" || die "无法进入应用目录：$APP_DIR"
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

    # 二次确认没有 openppp2 容器在运行
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
  echo "  openppp2 一键部署脚本"
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
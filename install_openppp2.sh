#!/usr/bin/env bash
# install_openppp2.sh — openppp2 Docker 一键部署主入口（v2.3 防卡死版）
#
# v2.3 关键改动（修复"一键脚本卡住"的根本原因）：
#   1) 引入全局超时常量：apt / curl / docker pull / compose up 都有硬超时
#   2) 非交互模式检测：管道 / 无 TTY 时所有 prompt 自动用默认值
#   3) prompt 加 5 分钟超时，绝不会永远阻塞
#   4) compose pull 失败 → 本地 Dockerfile 现场构建（避免依赖 GHCR 镜像存在）
#   5) health_check_one 改为带进度反馈、40s 总超时
#   6) 关键阶段加 step() 输出，让用户清楚卡在哪一步
#   7) Docker daemon 启动 / dpkg lock 等待都有显式超时
#
# 调试：export OPENPPP2_DEBUG=1 启用 set -x
# 完全无人值守：export OPENPPP2_NONINTERACTIVE=1 配合各种参数环境变量

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
#  do_install — 主安装流程
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
    1) step "准备 Docker 环境（server 模式）..."; ensure_docker_stack "server" ;;
    2) step "准备 Docker 环境（client 模式）..."; ensure_docker_stack "client" ;;
    *) die "角色选择错误，只能输入 1 或 2。" ;;
  esac

  local IMAGE BASE_URL
  prompt IMAGE    "请输入镜像地址" "${DEFAULT_IMAGE}"
  prompt BASE_URL "请输入基准配置文件 URL" "${DEFAULT_BASE_CFG_URL}"

  download_base_cfg "$BASE_URL"
  safer_cd "$APP_DIR"

  generate_seccomp_profile "$SECCOMP_FILE"

  local proxy_configured=0
  local proxy_cleanup_deferred=0

  if [[ "$ROLE" == "1" ]]; then
    # ============== 服务端配置 ==============
    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入服务端配置文件名" "appsettings.json"

    local SERVER_PUBLIC_IP autoip=""
    # 自动检测公网 IP（带超时，失败不阻塞）
    info "尝试自动检测公网 IP（最多 ${NET_TIMEOUT}s）..."
    autoip="$(curl_retry -sS https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$autoip" ]]; then
      prompt SERVER_PUBLIC_IP "请输入服务端对外（公网）IP" "$autoip"
    else
      warn "公网 IP 自动检测失败（网络问题或被墙），请手动输入"
      prompt SERVER_PUBLIC_IP "请输入服务端对外（公网）IP" ""
    fi
    [[ -z "$SERVER_PUBLIC_IP" ]] && die "服务端公网 IP 不能为空"

    local SERVER_BIND_IP
    prompt SERVER_BIND_IP "请输入服务端监听 bind IP（NAT 填内网 IP，直连填公网 IP）" "${SERVER_PUBLIC_IP}"

    jq --arg ip "$SERVER_PUBLIC_IP" \
       --arg bind "$SERVER_BIND_IP" \
       '.ip.public=$ip | .ip.interface=$bind' \
       appsettings.base.json > "$APP_CFG_NAME"

    write_compose_server "$IMAGE" "$APP_CFG_NAME"
    echo "server" > "${APP_DIR}/.role"

  elif [[ "$ROLE" == "2" ]]; then
    # ============== 客户端配置 ==============
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：宿主机不支持 TUN，client 无法运行。请尝试：sudo modprobe tun"

    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入客户端配置文件名" "appsettings.json"

    local MAIN_SERVICE_NAME
    prompt MAIN_SERVICE_NAME "请输入主客户端实例名称" "openppp2"

    local SERVER_IP SERVER_PORT guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端 IP" ""
    [[ -z "$SERVER_IP" ]] && die "服务端 IP 不能为空"
    prompt_port SERVER_PORT "请输入服务端端口" "20000"

    guid="$(gen_guid)"

    info "自动探测网络环境（本地命令，不发送网络请求）..."
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"
    netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"
    gw="${netinfo#*|}"

    if [[ -z "${lan:-}" || "${lan:-}" =~ ^10\. ]]; then
      warn "自动检测到的 LAN IP 为空或为 10.x（可能是隧道），请手动输入"
      prompt lan "请输入客户端内网 IP（如 192.168.1.100）" ""
    else
      info "检测到 LAN IP：${lan}"
    fi

    if [[ -z "${nic:-}" ]]; then
      warn "未能自动检测默认网卡，请手动输入"
      prompt nic "请输入默认网卡名（如 eth0、ens3、ens192）" ""
    else
      info "检测到默认网卡：${nic}"
    fi

    if [[ -z "${gw:-}" ]]; then
      warn "未能自动检测默认网关，请手动输入"
      prompt gw "请输入默认网关（如 192.168.1.1）" ""
    else
      info "检测到默认网关：${gw}"
    fi
    [[ -z "${gw:-}" ]] && die "网关地址不能为空"

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

    [[ -f ip.txt ]]        || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    enable_ip_forward_host

    local tun_name="ppp0" tun_ip="10.0.0.2" tun_gw="10.0.0.1"

    local USE_MUX
    prompt USE_MUX "是否开启 mux？(yes/no)" "no"
    write_compose_client "$IMAGE" "$nic" "$gw" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME" "$tun_name" "$tun_ip" "$tun_gw" "$USE_MUX"

    echo "client" > "${APP_DIR}/.role"
    echo "$MAIN_SERVICE_NAME" > "${APP_DIR}/.client_main_service"

    echo
    echo "当前客户端配置信息："
    echo "  配置文件：${APP_CFG_NAME}"
    echo "  server  ：${SERVER_URI}"
    echo "  SOCKS5  ：${lan}:${SOCKS_PORT}"
    echo "  HTTP    ：${lan}:${HTTP_PORT}"

    echo
    local USE_PROXY
    prompt USE_PROXY "是否为 Docker 配置 HTTP 代理来拉取镜像？(yes/no)" "no"
    if [[ "$USE_PROXY" == "yes" ]]; then
      local PROXY_IP PROXY_PORT
      prompt PROXY_IP "请输入代理服务器 IP" ""
      prompt_port PROXY_PORT "请输入代理服务器端口" "7890"

      if setup_docker_proxy "$PROXY_IP" "$PROXY_PORT"; then
        proxy_configured=1
      else
        warn "代理配置失败，将不使用代理继续"
      fi
    fi
  else
    die "角色选择错误，只能输入 1 或 2"
  fi

  # ============== 拉取镜像（带本地构建 fallback）==============
  pull_with_fallback "$APP_DIR"

  if [[ "$ROLE" == "2" ]]; then
    cleanup_docker_proxy_after_pull "$proxy_configured"
    if [[ "$proxy_configured" -eq 1 ]]; then
      proxy_cleanup_deferred=1
    fi
  fi

  # ============== 启动 stack ==============
  compose_up_safe "$APP_DIR"

  # ============== 健康检查 ==============
  if [[ "$ROLE" == "2" ]]; then
    local main_svc
    main_svc="$(cat "${APP_DIR}/.client_main_service" 2>/dev/null || echo openppp2)"
    health_check_one "$main_svc" || warn "健康检查未通过，请手动检查容器：docker logs ${main_svc}"
  else
    health_check_one "openppp2" || warn "健康检查未通过，请手动检查容器：docker logs openppp2"
  fi

  # ============== systemd 集成 ==============
  setup_systemd_weekly_update

  # ============== 收尾 ==============
  safer_back

  if [[ "$ROLE" == "2" && "$proxy_cleanup_deferred" -eq 1 ]]; then
    echo
    warn "Docker 代理配置文件已删除，但 daemon 尚未重启（避免打断 openppp2 容器）"
    warn "若要让 Docker 立即丢弃旧代理：sudo systemctl restart docker"
    warn "（重启后 openppp2 会因 restart:unless-stopped 自动拉起）"
  fi

  echo
  echo "===== 安装完成 ====="
  echo "  配置目录：${APP_DIR}"
  echo "  查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f"
  echo "  容器状态：${COMPOSE_KIND} -f ${COMPOSE_FILE} ps"
  echo
  info "安全：自定义 seccomp + cap_drop ALL + no-new-privileges + 非 root 用户 + 资源限制"
}

# ============================================================
#  do_uninstall — 卸载
# ============================================================
do_uninstall() {
  info "开始卸载 openppp2（不卸载 Docker）..."

  if has_systemd; then
    timeout 15 systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
    timeout 15 systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh \
        /etc/systemd/system/openppp2-boot.service \
        /usr/local/bin/openppp2-wait-uptime.sh \
        /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
  if has_systemd; then
    timeout 10 systemctl daemon-reload >/dev/null 2>&1 || true
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
    safer_cd "$APP_DIR"
    detect_compose >/dev/null 2>&1 || true
    if [[ -n "$COMPOSE_KIND" ]] && [[ -f "$COMPOSE_FILE" ]]; then
      info "清理 compose 资源..."
      timeout 60 "$COMPOSE_KIND" down --remove-orphans >/dev/null 2>&1 || true
    fi
    safer_back
  fi

  local KEEP_BACKUP
  prompt KEEP_BACKUP "是否保留备份文件？(yes/no)" "yes"

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
        warn "以下容器仍在运行：$running"
        die "卸载中止：仍有运行中的容器"
      fi
    fi

    info "删除目录 ${APP_DIR}..."
    rm -rf "$APP_DIR"

    if [[ -n "$tmp_backup" && -d "$tmp_backup" ]]; then
      mkdir -p "$APP_DIR"
      mv "$tmp_backup" "$BACKUP_DIR" >/dev/null 2>&1 || true
    fi
  else
    info "删除目录 ${APP_DIR}..."
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
  echo "  5) 删除客户端实例/配置"
  echo "  6) 备份当前配置文件"
  echo "  7) 回滚（恢复最新备份）"
  echo "=============================="

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    info "[非交互模式] stdin 不是终端，将使用环境变量或默认值"
  fi

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
    *) die "输入错误，只能是 1 / 2 / 3 / 4 / 5 / 6 / 7" ;;
  esac
}

main "$@"

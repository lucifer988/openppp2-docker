#!/usr/bin/env bash
# lib/client.sh — Modular library for openppp2-docker
# Auto-refactored from install_openppp2.sh

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === do_add_client ===
do_add_client() {
  ensure_docker_stack "client"

  if [[ ! -d "$APP_DIR" ]] || [[ ! -f "$COMPOSE_FILE" ]]; then
    die "未检测到已有安装，请先用 1) 安装 openppp2（client）后再用 3) 新增。"
  fi

  local role="unknown"
  if [[ -f "${APP_DIR}/.role" ]]; then
    role="$(cat "${APP_DIR}/.role" 2>/dev/null || echo unknown)"
  fi
  if [[ "$role" != "client" ]]; then
    die "当前安装不是 client（可能是 server），按要求禁止使用 3) 新增。"
  fi

  cd "$APP_DIR"

  if [[ ! -f "$SECCOMP_FILE" ]]; then
    info "未找到 seccomp 配置文件，正在生成..."
    generate_seccomp_profile "$SECCOMP_FILE"
  fi

  if [[ ! -f appsettings.base.json ]]; then
    local BASE_URL
    prompt BASE_URL "未找到 appsettings.base.json，请输入 URL" "${DEFAULT_BASE_CFG_URL}"
    download_base_cfg "$BASE_URL"
  fi

  local IMAGE
  IMAGE="$(awk '/image:/ {print $2; exit}' "$COMPOSE_FILE" 2>/dev/null || true)"
  if [[ -z "$IMAGE" ]]; then
    prompt IMAGE "未能解析镜像地址，请输入镜像地址" "${DEFAULT_IMAGE}"
  fi

  local SERVER_IP SERVER_PORT guid lan nic gw netinfo
  prompt SERVER_IP "请输入新增客户端要连接的服务端 IP（例如 1.2.3.4）" ""
  prompt_port SERVER_PORT "请输入新增客户端要连接的服务端端口（例如 20000）" "20000"

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

  local idx=2
  while grep -qE "^[[:space:]]{2}openppp2-${idx}:[[:space:]]*$" "$COMPOSE_FILE" 2>/dev/null; do
    idx=$(( idx + 1 ))
  done
  local default_svc="openppp2-${idx}"

  local SVC_NAME
  prompt SVC_NAME "请输入新客户端实例名称（容器/服务名）" "$default_svc"

  if grep -qE "^[[:space:]]{2}${SVC_NAME}:[[:space:]]*$" "$COMPOSE_FILE" 2>/dev/null; then
    die "服务名 ${SVC_NAME} 已存在，请换一个名称。"
  fi

  local cfg_default="appsettings-${SVC_NAME}.json"
  local CFG_NAME
  prompt CFG_NAME "请输入该客户端配置文件名称" "$cfg_default"

  local ipfile="ip-${SVC_NAME}.txt"
  local dnsfile="dns-rules-${SVC_NAME}.txt"

  local tun_idx="$idx"
  local tun_ip="10.0.${tun_idx}.2"
  local tun_gw="10.0.${tun_idx}.1"
  local tun_name="ppp${tun_idx}"

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
     appsettings.base.json > "${CFG_NAME}"

  [[ -f "$ipfile" ]] || : > "$ipfile"
  [[ -f "$dnsfile" ]] || : > "$dnsfile"

  enable_ip_forward_host

  local USE_MUX
  unset USE_MUX
  prompt USE_MUX "是否开启 mux？(yes/no)" "no"
  append_compose_client "${IMAGE}" "${nic}" "${gw}" "${SVC_NAME}" "${CFG_NAME}" "${ipfile}" "${dnsfile}" "${tun_name}" "${tun_ip}" "${tun_gw}" "$USE_MUX"

  echo
  local USE_PROXY
  prompt USE_PROXY "是否需要为 Docker 配置 HTTP 代理来拉取镜像？（yes/no）" "no"

  local proxy_configured=0
  local proxy_cleanup_deferred=0
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

  info "预拉取镜像..."
  compose pull "${SVC_NAME}" || compose pull || true

  cleanup_docker_proxy_after_pull "$proxy_configured"
  if [[ "$proxy_configured" -eq 1 ]]; then
    proxy_cleanup_deferred=1
    info "已完成镜像拉取，Docker 代理将在本次新增结束后保留为未生效状态（配置文件已删，未重启 daemon）。"
  fi

  info "启动新增客户端实例：${SVC_NAME} ..."
  compose up -d --remove-orphans "${SVC_NAME}"

  health_check_one "${SVC_NAME}" || warn "健康检查未通过，请手动检查容器状态"

  if [[ "$proxy_cleanup_deferred" -eq 1 ]]; then
    echo
    warn "注意：Docker 代理配置文件已删除，但当前 Docker daemon 尚未重启。"
    warn "这样做是为了避免刚启动的 ${SVC_NAME} 容器被 Docker 重启顺手停掉。"
    warn "如果你后续确实要让 Docker 立即丢弃旧代理，请手动执行：systemctl restart docker"
    warn "执行后 ${SVC_NAME} 会因 restart: unless-stopped 自动拉起。"
  fi

  echo
  echo "当前新增客户端配置信息："
  echo "  配置文件：${CFG_NAME}"
  echo "  server   ：${SERVER_URI}"
  echo "  SOCKS5   ：${lan}:${SOCKS_PORT}"
  echo "  HTTP     ：${lan}:${HTTP_PORT}"
  echo "  tun-host ：no（已强制写入命令行参数）"
  echo
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f ${SVC_NAME}"
}


# === do_show_info ===
do_show_info() {
  [[ -d "$APP_DIR" ]] || die "未检测到 ${APP_DIR} 目录，似乎尚未安装 openppp2。"
  cd "$APP_DIR"

  local found=0
  for f in appsettings*.json; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "appsettings.base.json" ]] && continue

    local server socks_bind socks_port http_bind http_port
    server="$(jq -r '(.client.server // empty)' "$f")"
    [[ -z "$server" ]] && continue

    socks_bind="$(jq -r '(.client["socks-proxy"].bind // "")' "$f")"
    socks_port="$(jq -r '(.client["socks-proxy"].port // "")' "$f")"
    http_bind="$(jq -r '(.client["http-proxy"].bind // "")' "$f")"
    http_port="$(jq -r '(.client["http-proxy"].port // "")' "$f")"

    found=1
    echo "----------------------------------------"
    echo "配置文件：$f"
    echo "  client.server ：$server"
    echo "  SOCKS5        ：${socks_bind}:${socks_port}"
    echo "  HTTP          ：${http_bind}:${http_port}"
  done

  if [[ "$found" -eq 0 ]]; then
    echo "未找到包含 client.server 的客户端配置文件。"
  else
    echo "----------------------------------------"
    echo "以上为当前所有客户端配置的 server / SOCKS5 / HTTP 信息"
  fi
}

CLIENT_CFG_LIST=()


# === list_client_cfgs ===
list_client_cfgs() {
  cd "$APP_DIR"
  CLIENT_CFG_LIST=()
  local f
  for f in appsettings*.json; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "appsettings.base.json" ]] && continue
    if jq -e '.client.server? // empty' "$f" >/dev/null 2>&1; then
      CLIENT_CFG_LIST+=("$f")
    fi
  done
  [[ "${#CLIENT_CFG_LIST[@]}" -gt 0 ]]
}


# === print_client_cfgs ===
print_client_cfgs() {
  local i=1
  local f
  for f in "${CLIENT_CFG_LIST[@]}"; do
    echo "  $i) $f" >&2
    i=$(( i + 1 ))
  done
}


# === find_service_by_cfg ===
find_service_by_cfg() {
  local cfg="$1"
  awk -v cfg="$cfg" '
    BEGIN{svc=""}
    /^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/ {svc=$1; sub(":", "", svc)}
    index($0, "./" cfg) > 0 { if (svc!="") { print svc; exit } }
  ' "$COMPOSE_FILE"
}


# === select_cfg_interactive ===
select_cfg_interactive() {
  echo >&2
  echo "可删除的客户端配置文件列表：" >&2
  print_client_cfgs
  echo >&2
  echo "你可以：" >&2
  echo "  - 输入编号（例如 2）" >&2
  echo "  - 或输入配置文件名/关键词（例如 RFCHK 或 appsettings-RFCHK.json）" >&2
  echo >&2

  local sel=""
  read -r -p "请输入要删除的配置（编号/名称/关键词）: " sel

  if [[ "$sel" =~ ^[0-9]+$ ]]; then
    local idx="$sel"
    local max_idx="${#CLIENT_CFG_LIST[@]}"
    if [[ "$idx" -ge 1 ]] && [[ "$idx" -le "$max_idx" ]]; then
      local arr_idx=$(( idx - 1 ))
      echo "${CLIENT_CFG_LIST[$arr_idx]}"
      return 0
    fi
    die "编号无效。"
  fi

  if [[ -f "${APP_DIR}/${sel}" ]]; then
    echo "$sel"
    return 0
  fi

  local matches=()
  local f
  for f in "${CLIENT_CFG_LIST[@]}"; do
    if [[ "$f" == *"$sel"* ]]; then
      matches+=("$f")
    fi
  done

  if [[ "${#matches[@]}" -eq 1 ]]; then
    echo "${matches[0]}"
    return 0
  fi

  if [[ "${#matches[@]}" -gt 1 ]]; then
    echo >&2
    warn "匹配到多个配置，请输入更精确的名称："
    local i=1
    for f in "${matches[@]}"; do
      echo "  $i) $f" >&2
      i=$(( i + 1 ))
    done
    die "请重新运行选项 5 并输入更精确的关键词/文件名。"
  fi

  die "未找到匹配的配置文件：$sel"
}


# === do_delete_client ===
do_delete_client() {
  ensure_docker_stack "client"

  [[ -d "$APP_DIR" ]] || die "未检测到 ${APP_DIR}，请先安装。"
  [[ -f "$COMPOSE_FILE" ]] || die "未找到 ${COMPOSE_FILE}，请先安装。"

  local role="unknown"
  if [[ -f "${APP_DIR}/.role" ]]; then
    role="$(cat "${APP_DIR}/.role" 2>/dev/null || echo unknown)"
  fi
  if [[ "$role" != "client" ]]; then
    die "当前环境不是 client（或未按脚本安装），为安全起见不提供删除。"
  fi

  cd "$APP_DIR"

  if ! list_client_cfgs; then
    echo "未找到可删除的客户端配置文件。"
    return 0
  fi

  local cfg
  cfg="$(select_cfg_interactive)"

  local svc=""
  svc="$(find_service_by_cfg "$cfg" || true)"

  echo
  echo "即将删除："
  echo "  配置文件：$cfg"
  echo "  对应服务：${svc:-（未能自动定位）}"
  echo

  local yesno
  prompt yesno "确认删除？输入 yes 继续" "no"
  if [[ "$yesno" != "yes" ]]; then
    echo "已取消。"
    return 0
  fi

  if [[ -n "$svc" ]]; then
    info "停止并移除 service/container：$svc"
    compose stop "$svc" >/dev/null 2>&1 || true
    compose rm -f "$svc" >/dev/null 2>&1 || true

    info "从 docker-compose.yml 移除 service：$svc"
    remove_service_block "$svc"

    rm -f "ip-${svc}.txt" "dns-rules-${svc}.txt" >/dev/null 2>&1 || true
  else
    warn "未能定位 service：将仅删除配置文件本身（若实例仍会被拉起，请手动从 docker-compose.yml 移除对应 service）。"
  fi

  info "删除配置文件：$cfg"
  rm -f "$cfg" >/dev/null 2>&1 || true

  info "清理孤儿并刷新运行状态..."
  compose up -d --remove-orphans >/dev/null 2>&1 || true

  echo
  echo "删除完成。建议用 4) 查看客户端配置和代理信息 确认结果。"
}


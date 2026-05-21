#!/usr/bin/env bash
# lib/client.sh — 客户端多实例管理：新增、查看、删除

SCRIPT_DIR_CLIENT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR_CLIENT}/config.sh" ]] && source "${SCRIPT_DIR_CLIENT}/config.sh"

# === list_client_services — 从 compose.yml 提取所有 client 服务名 ===
list_client_services() {
  [[ -f "$COMPOSE_FILE" ]] || return 0
  awk '/^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/ {gsub(/[: ]/,""); print}' "$COMPOSE_FILE"
}

# === pick_next_tun_segment — 找下一个可用 TUN 段（10.0.N.0/30）===
pick_next_tun_segment() {
  local used_ns
  used_ns="$(grep -oE 'ppp[0-9]+' "$COMPOSE_FILE" 2>/dev/null | sed 's/ppp//' | sort -un)"
  local n=2
  while echo "$used_ns" | grep -qx "$n"; do
    n=$((n+1))
  done
  echo "$n"
}

# === do_add_client — 新增客户端实例 ===
do_add_client() {
  [[ -f "$COMPOSE_FILE" ]] || die "${COMPOSE_FILE} 不存在，请先安装"

  local role=""
  [[ -f "${APP_DIR}/.role" ]] && role="$(cat "${APP_DIR}/.role")"
  if [[ "$role" != "client" ]]; then
    die "当前部署不是 client 模式（.role=${role}），无法新增 client 实例"
  fi

  ensure_docker_stack "client"
  safer_cd "$APP_DIR"

  local IMAGE
  prompt IMAGE "请输入镜像地址" "${DEFAULT_IMAGE}"

  local SVC
  local n
  n="$(pick_next_tun_segment)"
  prompt SVC "请输入新实例的服务名" "openppp2-${n}"

  if grep -qE "^[[:space:]]{2}${SVC}:[[:space:]]*$" "$COMPOSE_FILE"; then
    safer_back
    die "服务名 ${SVC} 已存在于 compose.yml"
  fi

  local CFG_NAME
  prompt CFG_NAME "请输入新实例的配置文件名" "appsettings-${SVC}.json"

  local SERVER_IP SERVER_PORT
  prompt SERVER_IP "请输入服务端 IP" ""
  prompt_port SERVER_PORT "请输入服务端端口" "20000"

  local netinfo lan nic gw
  netinfo="$(detect_net)"
  lan="${netinfo%%|*}"
  netinfo="${netinfo#*|}"
  nic="${netinfo%%|*}"
  gw="${netinfo#*|}"

  [[ -z "$lan" ]] && prompt lan "请输入客户端内网 IP" ""
  [[ -z "$nic" ]] && prompt nic "请输入默认网卡名" ""
  [[ -z "$gw"  ]] && prompt gw  "请输入默认网关" ""

  [[ -z "$gw" ]] && { safer_back; die "网关不能为空"; }

  local guid HTTP_PORT SOCKS_PORT SERVER_URI
  guid="$(gen_guid)"
  HTTP_PORT="$(random_free_port)"
  SOCKS_PORT="$(random_free_port)"
  while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do
    SOCKS_PORT="$(random_free_port)"
  done
  SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

  jq --arg srv "$SERVER_URI" \
     --arg guid "$guid" \
     --arg lan "$lan" \
     --argjson hport "$HTTP_PORT" \
     --argjson sport "$SOCKS_PORT" \
     '.client.server=$srv | .client.guid=$guid | .client["http-proxy"].bind=$lan | .client["socks-proxy"].bind=$lan | .client["http-proxy"].port=$hport | .client["socks-proxy"].port=$sport' \
     appsettings.base.json > "$CFG_NAME"

  local IPFILE="ip-${SVC}.txt" DNSFILE="dns-rules-${SVC}.txt"
  [[ -f "$IPFILE" ]]  || : > "$IPFILE"
  [[ -f "$DNSFILE" ]] || : > "$DNSFILE"

  local tun_name="ppp${n}"
  local tun_ip="10.0.${n}.2"
  local tun_gw="10.0.${n}.1"

  local USE_MUX
  prompt USE_MUX "是否开启 mux？(yes/no)" "no"
  append_compose_client "$IMAGE" "$nic" "$gw" "$SVC" "$CFG_NAME" "$IPFILE" "$DNSFILE" "$tun_name" "$tun_ip" "$tun_gw" "$USE_MUX"

  pull_with_fallback "$APP_DIR"
  compose_up_safe "$APP_DIR"
  health_check_one "$SVC" || warn "实例 ${SVC} 健康检查未通过"

  echo
  echo "===== 新增完成 ====="
  echo "  服务名 ：${SVC}"
  echo "  配置  ：${CFG_NAME}"
  echo "  server：${SERVER_URI}"
  echo "  SOCKS5：${lan}:${SOCKS_PORT}"
  echo "  HTTP  ：${lan}:${HTTP_PORT}"
  safer_back
}

# === do_show_info — 列出所有客户端实例的配置 ===
do_show_info() {
  [[ -f "$COMPOSE_FILE" ]] || die "${COMPOSE_FILE} 不存在，请先安装"

  echo
  echo "===== 客户端配置 ====="
  local svc cfg server sock http bind

  while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    cfg="$(awk -v s="^[[:space:]]{2}${svc}:" '$0 ~ s {found=1; next} found && /--config=/ {gsub(/.*=/,""); gsub(/"/,""); print; exit}' "$COMPOSE_FILE")"
    [[ -z "$cfg" ]] && cfg="appsettings.json"
    if [[ -f "${APP_DIR}/${cfg}" ]]; then
      server="$(jq -r '.client.server // empty' "${APP_DIR}/${cfg}" 2>/dev/null)"
      bind="$(jq -r '.client["http-proxy"].bind // empty' "${APP_DIR}/${cfg}" 2>/dev/null)"
      sock="$(jq -r '.client["socks-proxy"].port // empty' "${APP_DIR}/${cfg}" 2>/dev/null)"
      http="$(jq -r '.client["http-proxy"].port // empty' "${APP_DIR}/${cfg}" 2>/dev/null)"
      echo
      echo "  服务  ：${svc}"
      echo "  配置  ：${cfg}"
      echo "  server：${server}"
      echo "  bind  ：${bind}"
      echo "  SOCKS5：${bind}:${sock}"
      echo "  HTTP  ：${bind}:${http}"
    fi
  done < <(list_client_services)
}

# === do_delete_client — 删除指定客户端实例 ===
do_delete_client() {
  [[ -f "$COMPOSE_FILE" ]] || die "${COMPOSE_FILE} 不存在"

  echo
  echo "当前 client 服务列表："
  local services=()
  local svc
  while IFS= read -r svc; do
    [[ -n "$svc" ]] && services+=("$svc")
  done < <(list_client_services)

  if [[ "${#services[@]}" -eq 0 ]]; then
    die "未发现任何 client 服务"
  fi

  local i=1
  for s in "${services[@]}"; do
    echo "  $i) $s"
    i=$((i+1))
  done

  local CHOICE
  prompt CHOICE "请输入要删除的服务编号" "1"
  [[ "$CHOICE" =~ ^[0-9]+$ ]] || die "无效编号：$CHOICE"
  [[ "$CHOICE" -ge 1 && "$CHOICE" -le "${#services[@]}" ]] || die "编号超出范围"
  local target="${services[$((CHOICE-1))]}"

  info "准备删除服务：${target}"
  if need_cmd docker; then
    docker rm -f "$target" >/dev/null 2>&1 || true
  fi

  remove_service_block "$target"
  rm -f "${APP_DIR}/appsettings-${target}.json" \
        "${APP_DIR}/ip-${target}.txt" \
        "${APP_DIR}/dns-rules-${target}.txt" 2>/dev/null || true

  info "已删除 ${target} 的服务定义和配置文件"
}

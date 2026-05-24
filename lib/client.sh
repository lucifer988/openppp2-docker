#!/usr/bin/env bash
# client.sh - 客户端多实例管理：新增、查看、删除
#
# 依赖 compose.sh 的注册表 ${APP_DIR}/.instances，每行字段（| 分隔）：
#   svc|cfg|tun|tun_ip|tun_gw|nic|ngw|http_port|socks_port|mux
#
# 设计要点：
#   - 每个实例自动分配独立的 TUN 名（ppp0/ppp2/ppp3...）、TUN 网段（10.0.N.0/30）、
#     空闲 http/socks 端口、独立配置文件 appsettings-<svc>.json。
#   - 共享密钥（kf / protocol-key / transport-key）必须与服务端一致：
#     新增实例时从已有实例配置里复用，复用不到则提示粘贴。
#   - SOCKS5 用户名/密码是客户端本地的，每个实例各自随机生成并打印。

# ---------- 工具：从已有实例配置里取出共享密钥 ----------
# 输出 "kf|protocol_key|transport_key"，取不到的字段为空
_read_shared_keys_from_existing() {
  local f kf pk tk
  for f in "$APP_DIR"/appsettings*.json; do
    [[ -e "$f" ]] || continue
    kf="$(jq -r '.key.kf // empty' "$f" 2>/dev/null)"
    pk="$(jq -r '.key["protocol-key"] // empty' "$f" 2>/dev/null)"
    tk="$(jq -r '.key["transport-key"] // empty' "$f" 2>/dev/null)"
    if [[ -n "$pk" && -n "$tk" ]]; then
      echo "${kf}|${pk}|${tk}"
      return 0
    fi
  done
  echo "||"
  return 1
}

# ---------- 工具：分配下一个实例编号 ----------
# 已有实例服务名形如 openppp2 / openppp2-2 / openppp2-3...
_next_instance_index() {
  local max=1 svc rest n
  local instfile
  instfile="$(_instances_file)"
  if [[ -f "$instfile" ]]; then
    while IFS='|' read -r svc rest; do
      [[ -z "$svc" ]] && continue
      if [[ "$svc" =~ -([0-9]+)$ ]]; then
        n="${BASH_REMATCH[1]}"
      else
        n=1
      fi
      ((n > max)) && max="$n"
    done <"$instfile"
  fi
  echo $((max + 1))
}

# ---------- 3) 新增客户端实例 ----------
do_add_client() {
  [[ -d "$APP_DIR" ]] || die "未发现安装目录：$APP_DIR，请先完成客户端安装（菜单 1）。"
  [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：宿主机不支持 TUN，client 无法运行。"
  ensure_pkgs jq curl openssl iproute2
  detect_compose >/dev/null 2>&1 || true

  local instfile
  instfile="$(_instances_file)"
  if [[ ! -f "$instfile" ]]; then
    die "未发现客户端实例注册表（${instfile}）。新增实例仅适用于已部署为客户端的主机。"
  fi

  local IMAGE
  IMAGE="$(cat "$(_image_file)" 2>/dev/null || echo "$DEFAULT_IMAGE")"

  local idx svc cfg tun tunip tungw
  idx="$(_next_instance_index)"
  svc="openppp2-${idx}"
  cfg="appsettings-${svc}.json"
  tun="ppp${idx}"
  tunip="10.0.${idx}.2"
  tungw="10.0.${idx}.1"

  info "将新增实例：${svc}（TUN ${tun} / ${tunip} ，网关 ${tungw}）"

  # 基准配置：优先用安装时下载到 APP_DIR 的 appsettings.base.json
  local base="${APP_DIR}/appsettings.base.json"
  [[ -f "$base" ]] || die "未找到基准配置 ${base}，无法生成实例配置。"

  # 服务端连接信息
  local SERVER_IP SERVER_PORT guid
  prompt SERVER_IP "请输入服务端 IP（例如 1.2.3.4）" ""
  prompt_port SERVER_PORT "请输入服务端端口（例如 20000）" "20000"
  [[ -n "$SERVER_IP" ]] || die "服务端 IP 不能为空。"
  guid="$(gen_guid)"
  local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

  # 共享密钥：从已有实例复用，复用不到则提示粘贴服务端凭据
  local sk kf pk tk
  sk="$(_read_shared_keys_from_existing || true)"
  kf="${sk%%|*}"
  sk="${sk#*|}"
  pk="${sk%%|*}"
  tk="${sk#*|}"
  if [[ -z "$pk" || -z "$tk" ]]; then
    warn "未能从已有实例读取共享密钥，请粘贴服务端的密钥（必须与服务端完全一致）。"
    prompt kf "请输入 key.kf（服务端 server-credentials.txt 中的数值）" ""
    prompt pk "请输入 protocol-key" ""
    prompt tk "请输入 transport-key" ""
  else
    info "已从已有实例复用共享密钥（protocol-key / transport-key / kf）。"
  fi
  [[ -n "$pk" && -n "$tk" ]] || die "protocol-key / transport-key 不能为空，否则无法与服务端互通。"

  # 网络探测
  local lan nic gw netinfo
  netinfo="$(detect_net)"
  lan="${netinfo%%|*}"
  netinfo="${netinfo#*|}"
  nic="${netinfo%%|*}"
  gw="${netinfo#*|}"
  [[ -n "$lan" && ! "$lan" =~ ^10\. ]] || prompt lan "请输入客户端内网 IP（用于 http/socks bind）" "127.0.0.1"
  [[ -n "$nic" ]] || prompt nic "请输入默认网卡名（例如 eth0、ens3）" "$DEFAULT_CLIENT_NIC"
  [[ -n "$gw" ]] || prompt gw "请输入默认网关（例如 192.168.1.1）" ""
  [[ -n "$gw" ]] || die "网关地址不能为空。"

  # 端口与本地 SOCKS 凭据（每实例随机）
  local HTTP_PORT SOCKS_PORT s_user s_pass
  HTTP_PORT="$(random_free_port)"
  SOCKS_PORT="$(random_free_port)"
  while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do SOCKS_PORT="$(random_free_port)"; done
  s_user="user_$(gen_secret 8)"
  s_pass="$(gen_password 20)"

  # 生成实例配置
  jq --argjson kf "${kf:-0}" \
    --arg pk "$pk" --arg tk "$tk" \
    --arg srv "$SERVER_URI" --arg guid "$guid" --arg lan "$lan" \
    --argjson hport "$HTTP_PORT" --argjson sport "$SOCKS_PORT" \
    --arg suser "$s_user" --arg spass "$s_pass" \
    '.key.kf=$kf
      | .key["protocol-key"]=$pk | .key["transport-key"]=$tk
      | .client.server=$srv | .client.guid=$guid
      | .client["http-proxy"].bind=$lan  | .client["http-proxy"].port=$hport
      | .client["socks-proxy"].bind=$lan | .client["socks-proxy"].port=$sport
      | .client["socks-proxy"].username=$suser | .client["socks-proxy"].password=$spass' \
    "$base" >"${APP_DIR}/${cfg}" || die "生成实例配置失败。"
  chmod 600 "${APP_DIR}/${cfg}" 2>/dev/null || true # 含密钥与 SOCKS5 凭据，禁止世界可读

  # 追加到注册表并重新渲染整份 compose
  echo "${svc}|${cfg}|${tun}|${tunip}|${tungw}|${nic}|${gw}|${HTTP_PORT}|${SOCKS_PORT}|0" >>"$instfile"
  render_client_compose

  enable_ip_forward_host

  info "拉取/构建镜像并启动新实例..."
  ensure_image "$IMAGE"
  (cd "$APP_DIR" && compose up -d --remove-orphans)

  health_check_one "$svc" "client" "${lan}|${HTTP_PORT}|${SOCKS_PORT}" ||
    warn "实例 ${svc} 健康检查未通过，可稍后用 docker logs ${svc} 查看。"

  echo
  echo "===== 新增实例完成 ====="
  echo "  实例名 ：${svc}"
  echo "  配置   ：${APP_DIR}/${cfg}"
  echo "  server ：${SERVER_URI}"
  echo "  SOCKS5 ：${lan}:${SOCKS_PORT}  用户名 ${s_user}  密码 ${s_pass}"
  echo "  HTTP   ：${lan}:${HTTP_PORT}"
}

# ---------- 4) 查看客户端配置和代理信息 ----------
do_show_info() {
  [[ -d "$APP_DIR" ]] || die "未发现安装目录：$APP_DIR"
  local instfile
  instfile="$(_instances_file)"
  if [[ ! -f "$instfile" ]]; then
    # 可能是服务端，或单文件客户端
    if [[ -f "${APP_DIR}/.role" && "$(cat "${APP_DIR}/.role")" == "server" ]]; then
      echo "当前主机角色：服务端（server）"
      [[ -f "$CREDENTIALS_FILE" ]] && {
        echo "服务端凭据（请妥善保存，客户端需要用到）："
        echo
        cat "$CREDENTIALS_FILE"
      }
      return 0
    fi
    die "未发现客户端实例注册表（${instfile}）。"
  fi

  echo "==============================="
  echo " 客户端实例列表"
  echo "==============================="
  local svc cfg tun tunip tungw nic ngw hport sport mux
  local srv suser spass bind
  while IFS='|' read -r svc cfg tun tunip tungw nic ngw hport sport mux; do
    [[ -z "$svc" ]] && continue
    srv="$(jq -r '.client.server // ""' "${APP_DIR}/${cfg}" 2>/dev/null)"
    bind="$(jq -r '.client["socks-proxy"].bind // ""' "${APP_DIR}/${cfg}" 2>/dev/null)"
    suser="$(jq -r '.client["socks-proxy"].username // ""' "${APP_DIR}/${cfg}" 2>/dev/null)"
    spass="$(jq -r '.client["socks-proxy"].password // ""' "${APP_DIR}/${cfg}" 2>/dev/null)"
    echo
    echo "实例：${svc}"
    echo "  配置文件 ：${cfg}"
    echo "  TUN      ：${tun}  ${tunip}/30  网关 ${tungw}"
    echo "  物理网卡 ：${nic}  物理网关 ${ngw}"
    echo "  server   ：${srv}"
    echo "  SOCKS5   ：${bind}:${sport}  用户名 ${suser}  密码 ${spass}"
    echo "  HTTP     ：${bind}:${hport}"
    if need_cmd docker; then
      local st
      st="$(docker inspect -f '{{.State.Status}}' "$svc" 2>/dev/null || echo 未创建)"
      echo "  容器状态 ：${st}"
    fi
  done <"$instfile"
  echo
}

# ---------- 5) 删除客户端实例 ----------
do_delete_client() {
  [[ -d "$APP_DIR" ]] || die "未发现安装目录：$APP_DIR"
  local instfile
  instfile="$(_instances_file)"
  [[ -f "$instfile" ]] || die "未发现客户端实例注册表（${instfile}）。"
  detect_compose >/dev/null 2>&1 || true

  # 列出实例供选择
  local -a svcs=()
  local svc rest i=0
  while IFS='|' read -r svc rest; do
    [[ -z "$svc" ]] && continue
    svcs+=("$svc")
  done <"$instfile"

  [[ ${#svcs[@]} -gt 0 ]] || die "没有可删除的实例。"

  echo "请选择要删除的实例："
  for i in "${!svcs[@]}"; do
    echo "  $((i + 1))) ${svcs[$i]}"
  done

  local pick
  prompt pick "请输入序号（1-${#svcs[@]}）" "1"
  [[ "$pick" =~ ^[0-9]+$ ]] && ((pick >= 1 && pick <= ${#svcs[@]})) ||
    die "序号无效。"

  local target="${svcs[$((pick - 1))]}"
  info "将删除实例：${target}"

  # 取该实例的配置文件名
  local tcfg=""
  while IFS='|' read -r svc rest; do
    if [[ "$svc" == "$target" ]]; then
      tcfg="${rest%%|*}"
      break
    fi
  done <"$instfile"

  # 删除前先备份 compose、注册表与该实例配置（保守起见，便于回滚）
  local ts snap
  ts="$(date +%Y%m%d_%H%M%S)"
  snap="${BACKUP_DIR}/del-${target}-${ts}"
  mkdir -p "$snap"
  [[ -f "$COMPOSE_FILE" ]] && cp -a "$COMPOSE_FILE" "$snap"/ 2>/dev/null || true
  [[ -f "$instfile" ]] && cp -a "$instfile" "$snap"/ 2>/dev/null || true
  [[ -n "$tcfg" && -f "${APP_DIR}/${tcfg}" ]] && cp -a "${APP_DIR}/${tcfg}" "$snap"/ 2>/dev/null || true
  info "已备份当前状态到：${snap}"

  # 先停掉并删除该容器（避免 restart: unless-stopped 反复拉起）
  if need_cmd docker; then
    docker rm -f "$target" >/dev/null 2>&1 || true
  fi

  # 从注册表移除该行
  local tmp
  tmp="$(mktemp)"
  grep -v -E "^${target}\|" "$instfile" >"$tmp" || true
  mv "$tmp" "$instfile"

  # 删除其配置文件
  [[ -n "$tcfg" && -f "${APP_DIR}/${tcfg}" ]] && rm -f "${APP_DIR}/${tcfg}"

  # 若仍有实例则重渲染并应用；否则保留空 compose
  if [[ -s "$instfile" ]]; then
    render_client_compose
    (cd "$APP_DIR" && compose up -d --remove-orphans) || true
  else
    warn "已删除最后一个实例，注册表为空。"
    : >"$COMPOSE_FILE"
  fi

  info "实例 ${target} 已删除。"
}

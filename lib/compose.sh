#!/usr/bin/env bash
# compose.sh - 生成 docker-compose.yml
#   - 服务端：单实例，直接写
#   - 客户端：用实例注册表 ${APP_DIR}/.instances 驱动，支持同机多实例
#
# 注册表每行字段（| 分隔）：
#   svc|cfg|tun|tun_ip|tun_gw|nic|ngw|http_port|socks_port|mux

INSTANCES_FILE_NAME=".instances"
IMAGE_REF_FILE_NAME=".image"

_instances_file() { echo "${APP_DIR}/${INSTANCES_FILE_NAME}"; }
_image_file() { echo "${APP_DIR}/${IMAGE_REF_FILE_NAME}"; }

# 公共片段：安全加固（cap 最小化 + no-new-privileges + seccomp）、资源上限、日志限制。
# 统一以 4 空格缩进输出，置于每个 service 之下，服务端/客户端复用，避免漏配/不一致。
#   - 容器进程虽仍以 root 运行（host 网络下创建 TUN/改路由/iptables 需要），但 cap_drop ALL
#     后只保留 NET_ADMIN（TUN/路由/iptables）与 NET_RAW（原始套接字/ICMP），其余特权全部丢弃；
#   - no-new-privileges 阻止通过 setuid 提权；
#   - 资源上限防止异常实例（内存泄漏/fork 失控）拖垮宿主机。
_compose_common_block() {
  cat <<EOF
    cap_drop: ["ALL"]
    cap_add: ["NET_ADMIN", "NET_RAW"]
    security_opt:
      - seccomp=./seccomp-openppp2.json
      - no-new-privileges:true
EOF
  [[ -n "${MEM_LIMIT}" ]] && echo "    mem_limit: \"${MEM_LIMIT}\""
  [[ -n "${PIDS_LIMIT}" ]] && echo "    pids_limit: ${PIDS_LIMIT}"
  [[ -n "${CPUS}" ]] && echo "    cpus: \"${CPUS}\""
  cat <<EOF
    logging:
      driver: json-file
      options:
        max-size: "${LOG_MAX_SIZE}"
        max-file: "${LOG_MAX_FILE}"
EOF
}

# ---------- 服务端 ----------
write_compose_server() {
  local image="$1" cfg="$2"
  echo "$image" >"$(_image_file)"
  cat >"$COMPOSE_FILE" <<EOF
# 由 install_openppp2.sh 自动生成（server）。务必在 ${APP_DIR} 目录下执行 compose。
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    command: ["--mode=server"]
$(_compose_common_block)
EOF
  info "已生成服务端 docker-compose.yml"
}

# ---------- 客户端：根据注册表渲染整份 compose ----------
render_client_compose() {
  local image instfile
  image="$(cat "$(_image_file)" 2>/dev/null || echo "$DEFAULT_IMAGE")"
  instfile="$(_instances_file)"
  {
    echo "# 由 install_openppp2.sh 自动生成（client，多实例）。务必在 ${APP_DIR} 目录下执行 compose。"
    echo "services:"
    local svc cfg tun tunip tungw nic ngw hport sport mux muxline
    while IFS='|' read -r svc cfg tun tunip tungw nic ngw hport sport mux; do
      [[ -z "$svc" ]] && continue
      muxline=""
      if [[ -n "$mux" && "$mux" != "0" && "$mux" != "no" ]]; then
        muxline=",\"--tun-mux\",\"${mux}\""
      fi
      cat <<EOF
  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    command: ["--mode=client","--tun","${tun}","--tun-ip","${tunip}","--tun-gw","${tungw}","--tun-mask","30","--tun-host=no","--nic","${nic}","--ngw","${ngw}"${muxline}]
$(_compose_common_block)
EOF
    done <"$instfile"
  } >"$COMPOSE_FILE"
}

# write_compose_client <image> <nic> <gw> <svc> <cfg> <tun> <tun_ip> <tun_gw> <mux yes|no>
write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun="$6" tunip="$7" tungw="$8" usemux="$9"
  echo "$image" >"$(_image_file)"

  local hport sport muxn
  hport="$(jq -r '.client["http-proxy"].port' "${APP_DIR}/${cfg}" 2>/dev/null || echo 0)"
  sport="$(jq -r '.client["socks-proxy"].port' "${APP_DIR}/${cfg}" 2>/dev/null || echo 0)"
  if [[ "$usemux" == "yes" ]]; then muxn=8; else muxn=0; fi

  echo "${svc}|${cfg}|${tun}|${tunip}|${tungw}|${nic}|${gw}|${hport}|${sport}|${muxn}" >"$(_instances_file)"
  render_client_compose
  info "已生成客户端 docker-compose.yml（实例：${svc}）"
}

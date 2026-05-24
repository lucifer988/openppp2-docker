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
_image_file()     { echo "${APP_DIR}/${IMAGE_REF_FILE_NAME}"; }

# ---------- 服务端 ----------
write_compose_server() {
  local image="$1" cfg="$2"
  echo "$image" > "$(_image_file)"
  cat > "$COMPOSE_FILE" <<EOF
# 由 install_openppp2.sh 自动生成（server）。务必在 ${APP_DIR} 目录下执行 compose。
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    network_mode: host
    cap_add: ["NET_ADMIN"]
    security_opt:
      - seccomp=./seccomp-openppp2.json
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    command: ["--mode=server"]
    logging:
      driver: json-file
      options:
        max-size: "${LOG_MAX_SIZE}"
        max-file: "${LOG_MAX_FILE}"
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
    cap_add: ["NET_ADMIN"]
    devices:
      - /dev/net/tun:/dev/net/tun
    security_opt:
      - seccomp=./seccomp-openppp2.json
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    command: ["--mode=client","--tun","${tun}","--tun-ip","${tunip}","--tun-gw","${tungw}","--tun-mask","30","--tun-host=no","--nic","${nic}","--ngw","${ngw}"${muxline}]
    logging:
      driver: json-file
      options:
        max-size: "${LOG_MAX_SIZE}"
        max-file: "${LOG_MAX_FILE}"
EOF
    done < "$instfile"
  } > "$COMPOSE_FILE"
}

# write_compose_client <image> <nic> <gw> <svc> <cfg> <tun> <tun_ip> <tun_gw> <mux yes|no>
write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun="$6" tunip="$7" tungw="$8" usemux="$9"
  echo "$image" > "$(_image_file)"

  local hport sport muxn
  hport="$(jq -r '.client["http-proxy"].port'  "${APP_DIR}/${cfg}" 2>/dev/null || echo 0)"
  sport="$(jq -r '.client["socks-proxy"].port' "${APP_DIR}/${cfg}" 2>/dev/null || echo 0)"
  if [[ "$usemux" == "yes" ]]; then muxn=8; else muxn=0; fi

  echo "${svc}|${cfg}|${tun}|${tunip}|${tungw}|${nic}|${gw}|${hport}|${sport}|${muxn}" > "$(_instances_file)"
  render_client_compose
  info "已生成客户端 docker-compose.yml（实例：${svc}）"
}

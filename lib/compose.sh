#!/usr/bin/env bash
# lib/compose.sh — Compose YAML 生成
#
# 安全相关（点 4）：
#   - cap_drop: [ALL] 后只白名单两个能力（NET_ADMIN / NET_RAW）
#   - security_opt: no-new-privileges:true 禁止 setuid 提权
#   - init: true 让 docker 注入 init 进程，配合镜像里的 tini 处理 PID 1
#   - 镜像本身以非 root 用户 ppp(uid=1000) 启动（USER 指令在 Dockerfile 里）
#
# 资源/日志（点 6）：
#   - deploy.resources.limits 给容器加内存 + CPU 上限
#   - logging.options.max-size / max-file 限制日志体积

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === compose_restart_policy_block ===
compose_restart_policy_block() {
  if [[ "${STRICT_BOOT_DELAY_MODE}" == "yes" ]]; then
    :
  else
    cat <<'RESTARTEOF'
    restart: unless-stopped
RESTARTEOF
  fi
}

# === compose_security_opt_block ===
# 三层加固：
#   1) seccomp profile（自定义版，仅放开 io_uring 所需调用）
#   2) apparmor=unconfined（避免某些发行版默认 profile 拒绝 TUN 操作）
#   3) no-new-privileges（即使容器内有 setuid 二进制也无法提权）
compose_security_opt_block() {
  cat <<'SECOPTEOF'
    security_opt:
      - seccomp=./seccomp-openppp2.json
      - apparmor=unconfined
      - no-new-privileges:true
SECOPTEOF
}

# === compose_capabilities_block ===
# 最小化 Linux capabilities：
#   - 先 drop ALL，去掉容器默认的一大堆能力（CAP_SYS_CHROOT、CAP_FOWNER 等都没用）
#   - 再 add 三个真正需要的：
#       NET_ADMIN: 创建 TUN 设备、改路由
#       NET_RAW:   ICMP / 原始套接字
#       NET_BIND_SERVICE: 非 root 用户绑定 <1024 的端口（mappings 里可能有 80）
compose_capabilities_block() {
  cat <<'CAPEOF'
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - NET_BIND_SERVICE
CAPEOF
}

# === compose_logging_block ===
compose_logging_block() {
  cat <<'LOGEOF'
    logging:
      driver: "json-file"
      options:
        max-size: "20m"
        max-file: "5"
LOGEOF
}

# === compose_resources_block ===
# 资源限制（compose v2 的 docker compose 在非 swarm 模式下也会尊重该字段）。
# 默认值偏宽，避免误伤；用户可通过环境变量覆盖。
compose_resources_block() {
  local mem_limit="${OPENPPP2_MEM_LIMIT:-512M}"
  local mem_reserve="${OPENPPP2_MEM_RESERVE:-64M}"
  local cpu_limit="${OPENPPP2_CPU_LIMIT:-1.0}"
  cat <<RESEOF
    deploy:
      resources:
        limits:
          cpus: '${cpu_limit}'
          memory: ${mem_limit}
        reservations:
          memory: ${mem_reserve}
RESEOF
}

# === compose_init_block ===
# 让 docker 注入 init 进程（即使老镜像没装 tini 也能正确收到 SIGTERM）
compose_init_block() {
  cat <<'INITEOF'
    init: true
INITEOF
}

# === write_compose_server ===
write_compose_server() {
  local image="$1" cfg="$2"
  : > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<SERVEREOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
$(compose_restart_policy_block)
$(compose_init_block)
$(compose_security_opt_block)
$(compose_capabilities_block)
$(compose_resources_block)
$(compose_logging_block)
    network_mode: host
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
SERVEREOF
}

# === write_compose_client ===
write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun_name="$6" tun_ip="$7" tun_gw="$8" use_mux="${9:-no}"
  : > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<CLIENTEOF
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
$(compose_restart_policy_block)
$(compose_init_block)
$(compose_security_opt_block)
$(compose_capabilities_block)
$(compose_resources_block)
$(compose_logging_block)
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./${cfg}:/opt/openppp2/${cfg}:ro
      - ./ip.txt:/opt/openppp2/ip.txt:ro
      - ./dns-rules.txt:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=${cfg}"
      - "--tun-host=no"
      - "--tun=${tun_name}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
      - "--tun-mask=30"
      - "--tun-vnet=yes"
      - "--tun-flash=no"
      - "--tun-static=no"
      - "--block-quic=yes"
      - "--bypass-iplist=/opt/openppp2/ip.txt"
      - "--dns-rules=/opt/openppp2/dns-rules.txt"
      - "--dns=8.8.8.8"
      - "--bypass-iplist-nic=${nic}"
      - "--bypass-iplist-ngw"
      - "${gw}"
CLIENTEOF
  if [[ "$use_mux" == "yes" ]]; then
    cat >> "$COMPOSE_FILE" <<MUXEOF
      - "--tun-mux=12"
      - "--tun-mux-acceleration=3"
      - "--tun-ssmt=4/st"
MUXEOF
  fi
}

# === append_compose_client ===
append_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" ipfile="$6" dnsfile="$7" tun_name="$8" tun_ip="$9" tun_gw="${10}" use_mux="${11:-no}"
  cat >> "$COMPOSE_FILE" <<APPENDEOF

  ${svc}:
    image: ${image}
    container_name: ${svc}
$(compose_restart_policy_block)
$(compose_init_block)
$(compose_security_opt_block)
$(compose_capabilities_block)
$(compose_resources_block)
$(compose_logging_block)
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./${cfg}:/opt/openppp2/${cfg}:ro
      - ./${ipfile}:/opt/openppp2/ip.txt:ro
      - ./${dnsfile}:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=${cfg}"
      - "--tun-host=no"
      - "--tun=${tun_name}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
      - "--tun-mask=30"
      - "--tun-vnet=yes"
      - "--tun-flash=no"
      - "--tun-static=no"
      - "--block-quic=yes"
      - "--bypass-iplist=/opt/openppp2/ip.txt"
      - "--dns-rules=/opt/openppp2/dns-rules.txt"
      - "--dns=8.8.8.8"
      - "--bypass-iplist-nic=${nic}"
      - "--bypass-iplist-ngw"
      - "${gw}"
APPENDEOF
  if [[ "$use_mux" == "yes" ]]; then
    cat >> "$COMPOSE_FILE" <<MUXEOF
      - "--tun-mux=12"
      - "--tun-mux-acceleration=3"
      - "--tun-ssmt=4/st"
MUXEOF
  fi
}

# === remove_service_block ===
remove_service_block() {
  local svc="$1"
  local tmp
  tmp="$(mktemp)"

  awk -v svc="$svc" '
    BEGIN{inblock=0}
    $0 ~ "^[[:space:]]{2}" svc ":[[:space:]]*$" {inblock=1; next}
    inblock==1 && $0 ~ "^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$" {inblock=0}
    inblock==1 {next}
    {print}
  ' "$COMPOSE_FILE" > "$tmp"

  mv "$tmp" "$COMPOSE_FILE"
}

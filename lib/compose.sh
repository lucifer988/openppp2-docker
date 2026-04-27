#!/usr/bin/env bash
# lib/compose.sh — Modular library for openppp2-docker
# Auto-refactored from install_openppp2.sh

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === compose_header ===
compose_header() {
  :  # Docker Compose V2 不再需要 version 字段
}


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
compose_security_opt_block() {
  cat <<'SECOPTEOF'
    security_opt:
      - seccomp=./seccomp-openppp2.json
      - apparmor=unconfined
SECOPTEOF
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


# === write_compose_server ===
write_compose_server() {
  local image="$1" cfg="$2"
  compose_header > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<SERVEREOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
$(compose_restart_policy_block)
$(compose_security_opt_block)
$(compose_logging_block)
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
SERVEREOF
}


# === write_compose_client ===
write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun_name="$6" tun_ip="$7" tun_gw="$8" use_mux="${9:-no}"
  compose_header > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<CLIENTEOF
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
$(compose_restart_policy_block)
$(compose_security_opt_block)
$(compose_logging_block)
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
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
$(compose_security_opt_block)
$(compose_logging_block)
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
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


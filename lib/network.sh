#!/usr/bin/env bash
# lib/network.sh — Modular library for openppp2-docker
# Auto-refactored from install_openppp2.sh

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === is_port_in_use ===
is_port_in_use() {
  local port="$1"
  ss -tuln 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/.*://g' | grep -qx "$port"
}


# === random_free_port ===
random_free_port() {
  local p tries=0
  while :; do
    p=$(( RANDOM % 50001 + 10000 ))
    if ! is_port_in_use "$p"; then
      echo "$p"
      return 0
    fi
    tries=$(( tries + 1 ))
    if [[ "$tries" -gt 200 ]]; then
      die "10000-60000 区间内未找到空闲端口，请检查端口占用情况。"
    fi
  done
}


# === detect_net ===
detect_net() {
  local out lan dev gw
  local forced=""

  if [[ -n "${CLIENT_NIC:-}" ]]; then
    forced="${CLIENT_NIC}"
    if ! ip link show "${forced}" >/dev/null 2>&1; then
      die "已设置 CLIENT_NIC=${CLIENT_NIC} 但系统未找到该网卡（ip link show 失败）。"
    fi
  else
    if ip link show "${DEFAULT_CLIENT_NIC}" >/dev/null 2>&1; then
      forced="${DEFAULT_CLIENT_NIC}"
    fi
  fi

  if [[ -n "${forced}" ]]; then
    dev="${forced}"
    lan="$(ip -4 addr show "$dev" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)" || true
    gw="$(ip -4 route show default dev "$dev" 2>/dev/null | awk 'NR==1{print $3}')" || true

    if [[ -n "${lan:-}" ]]; then
      if [[ -z "${gw:-}" ]]; then
        gw="$(ip -4 route show default 2>/dev/null | awk 'NR==1{print $3}')" || true
      fi
      echo "${lan:-}|${dev:-}|${gw:-}"
      return 0
    fi

    if [[ -n "${CLIENT_NIC:-}" ]]; then
      die "CLIENT_NIC=${CLIENT_NIC} 存在但未获取到 IPv4 地址，无法作为客户端 LAN 绑定。"
    fi
    warn "默认客户端网卡 ${forced} 未获取到 IPv4，回退自动探测逻辑。"
  fi

  dev="$(ip -4 route show default 2>/dev/null | awk 'NR==1{print $5}')" || true
  gw="$(ip -4 route show default 2>/dev/null | awk 'NR==1{print $3}')" || true

  if [[ -n "${dev:-}" ]]; then
    lan="$(ip -4 addr show "$dev" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)" || true
  fi

  if [[ -z "${dev:-}" || -z "${lan:-}" ]]; then
    out="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
    lan="$(awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")"
    dev="${dev:-$(awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")}"
    gw="${gw:-$(awk '/via/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$out")}"
  fi

  if [[ "${dev:-}" =~ ^(ppp|tun|wg|tailscale|docker|br-|virbr|lo) ]] || [[ "${lan:-}" =~ ^10\. ]]; then
    local cand cand_ip
    cand="$(ip -o link show up | awk -F': ' '{print $2}' | grep -Ev '^(lo|ppp|tun|wg|tailscale|docker|br-|virbr)' | head -n1 || true)"
    if [[ -n "$cand" ]]; then
      cand_ip="$(ip -4 addr show "$cand" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)" || true
      if [[ -n "$cand_ip" ]]; then
        dev="$cand"
        lan="$cand_ip"
      fi
    fi
  fi

  echo "${lan:-}|${dev:-}|${gw:-}"
}


# === enable_ip_forward_host ===
enable_ip_forward_host() {
  info "尝试开启宿主机 IPv4 转发（client 需要）..."
  if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    cat >/etc/sysctl.d/99-openppp2.conf <<'SYSCTLEOF'
net.ipv4.ip_forward=1
SYSCTLEOF
    sysctl --system >/dev/null 2>&1 || true
  else
    warn "sysctl 写入失败（可能权限受限）。你可手动执行：sysctl -w net.ipv4.ip_forward=1"
  fi
}


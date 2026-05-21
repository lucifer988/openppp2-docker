#!/usr/bin/env bash
# lib/network.sh — 网络探测：网卡、IP、网关、空闲端口、IP 转发
#
# v2.3 防卡死改动：
#   1) detect_net 全部用本地命令，不发任何网络请求，绝不会卡
#   2) random_free_port 有最大尝试次数限制，不再可能死循环
#   3) enable_ip_forward_host 写文件失败就 warn 而不是阻塞

SCRIPT_DIR_NET="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR_NET}/config.sh" ]] && source "${SCRIPT_DIR_NET}/config.sh"

# === detect_net — 自动探测 LAN_IP|NIC|GATEWAY ===
# 返回值通过 stdout: "192.168.1.100|ens192|192.168.1.1"
# 完全靠本地 ip route，没有网络请求。失败的字段返回空字符串。
detect_net() {
  local lan="" nic="" gw=""

  # 优先从默认路由提取
  local route_line
  route_line="$(ip -4 route show default 2>/dev/null | head -1 || true)"
  if [[ -n "$route_line" ]]; then
    # 格式： default via 192.168.1.1 dev ens192 proto dhcp src 192.168.1.100 metric 100
    gw="$(echo "$route_line"  | awk '{for(i=1;i<=NF;i++) if($i=="via")  print $(i+1)}')"
    nic="$(echo "$route_line" | awk '{for(i=1;i<=NF;i++) if($i=="dev")  print $(i+1)}')"
    lan="$(echo "$route_line" | awk '{for(i=1;i<=NF;i++) if($i=="src")  print $(i+1)}')"
  fi

  # src 如果没有，从网卡的第一个 IPv4 地址取
  if [[ -z "$lan" && -n "$nic" ]]; then
    lan="$(ip -4 -o addr show dev "$nic" 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1 || true)"
  fi

  # 用户通过 CLIENT_NIC 强制指定网卡
  if [[ -n "${CLIENT_NIC:-}" ]]; then
    nic="$CLIENT_NIC"
    lan="$(ip -4 -o addr show dev "$nic" 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1 || true)"
  fi

  echo "${lan}|${nic}|${gw}"
}

# === random_free_port — 随机找一个未占用端口（10000-60000）===
# v2.3: 最多尝试 100 次，超过就 die，绝不死循环
random_free_port() {
  local port tries=0
  while [[ $tries -lt 100 ]]; do
    port=$(( (RANDOM % 50000) + 10000 ))
    if ! ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE ":${port}\$"; then
      echo "$port"
      return 0
    fi
    tries=$((tries+1))
  done
  die "无法在 10000-60000 区间找到空闲端口（已尝试 100 次），可能 ss 命令异常或端口耗尽。"
}

# === port_in_use — 检查指定端口是否被占用 ===
port_in_use() {
  local port="$1"
  ss -lntu 2>/dev/null | awk '{print $5}' | grep -qE ":${port}\$"
}

# === enable_ip_forward_host — 启用宿主机 IP 转发 ===
enable_ip_forward_host() {
  local cfg="/etc/sysctl.d/99-openppp2.conf"
  if [[ -f "$cfg" ]]; then
    info "IP 转发配置已存在：$cfg"
  else
    info "启用 IPv4/IPv6 转发..."
    cat > "$cfg" <<'IPFWDEOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
IPFWDEOF
  fi
  if need_cmd sysctl; then
    sysctl --system >/dev/null 2>&1 || warn "sysctl --system 失败（可能影响 IP 转发，但不阻断安装）"
  fi
}

# === ping_check — 快速测试目标可达 ===
# 仅返回 0/1，最长 3 秒，永远不会卡
ping_check() {
  local host="$1"
  if need_cmd ping; then
    ping -c 1 -W 3 "$host" >/dev/null 2>&1
  else
    return 1
  fi
}

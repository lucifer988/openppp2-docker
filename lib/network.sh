#!/usr/bin/env bash
# network.sh - 网络工具：网卡/IP/网关探测、空闲端口、IP 转发

# 端口是否被占用（0=占用）
port_in_use() {
  local p="$1"
  if need_cmd ss; then
    ss -Hltun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${p}\$"
  elif need_cmd netstat; then
    netstat -tuln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}\$"
  else
    return 1
  fi
}

# random_free_port -> 10000-60000 之间的空闲端口
random_free_port() {
  local p tries=0
  while ((tries < 200)); do
    p=$(((RANDOM % 50000) + 10000))
    if ! port_in_use "$p"; then
      echo "$p"
      return 0
    fi
    tries=$((tries + 1))
  done
  die "无法在 10000-60000 范围内找到空闲端口。"
}

# detect_net -> 输出 "LAN_IP|NIC|GATEWAY"
detect_net() {
  local lan="" nic="" gw=""
  if need_cmd ip; then
    # 用到公网的默认路由来推断 dev / src / via
    local line
    line="$(ip -o route get 1.1.1.1 2>/dev/null | head -n1)"
    nic="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$line")"
    gw="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$line")"
    lan="$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$line")"
    [[ -z "$gw" ]] && gw="$(ip -o route show default 2>/dev/null | awk '{print $3; exit}')"
    [[ -z "$nic" ]] && nic="$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  fi
  echo "${lan}|${nic}|${gw}"
}

# 开启宿主机 IP 转发（client 需要）
enable_ip_forward_host() {
  info "开启宿主机 IPv4 转发..."
  cat >/etc/sysctl.d/99-openppp2.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
EOF
  sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
}

#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"

DEFAULT_IMAGE="ghcr.io/lucifer988/openppp2:latest"
DEFAULT_BASE_CFG_URL="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

COMPOSE_KIND="" # "docker compose" or "docker-compose"

need_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
has_systemd() { [[ -d /run/systemd/system ]] && need_cmd systemctl; }

die() { echo -e "[!]\t$*" >&2; exit 1; }
info() { echo -e "[*]\t$*"; }
warn() { echo -e "[!]\t$*" >&2; }

# 通用交互函数：支持同名环境变量覆盖
prompt() {
  local __var="$1" __msg="$2" __def="${3:-}"
  local __val=""

  local __env_val="${!__var-}"
  if [[ -n "$__env_val" ]]; then
    __val="$__env_val"
    printf -v "$__var" "%s" "$__val"
    info "使用环境变量 ${__var}=${__val}"
    return 0
  fi

  if [[ -n "$__def" ]]; then
    read -r -p "$__msg [$__def]: " __val
    __val="${__val:-$__def}"
  else
    read -r -p "$__msg: " __val
  fi
  printf -v "$__var" "%s" "$__val"
}

compose() {
  if [[ "$COMPOSE_KIND" == "docker compose" ]]; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

detect_compose() {
  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker compose"
    return 0
  fi
  if need_cmd docker-compose && docker-compose version >/dev/null 2>&1; then
    COMPOSE_KIND="docker-compose"
    return 0
  fi
  COMPOSE_KIND=""
  return 1
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "$@"
}

curl_retry() {
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 --max-time 120 "$@"
}

ensure_basic_tools() {
  # 尽量装上这些工具；如果 apt 不存在，就只能靠系统已有的
  if need_cmd apt-get; then
    apt_install ca-certificates curl jq iproute2 gnupg 2>/dev/null || true
  fi
  need_cmd curl || die "curl 未安装成功，请手动安装 curl 后重试。"
  need_cmd jq   || die "jq 未安装成功，请手动安装 jq 后重试。"
  need_cmd ip   || die "ip 命令未找到，请安装 iproute2 后重试。"
  need_cmd ss   || die "ss 命令未找到，请安装 iproute2 / iproute2-ss 后重试。"
}

start_docker_daemon_soft() {
  # 尽量把 docker 拉起来，失败就提示，不死磕
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service docker start >/dev/null 2>&1 || true
  fi
}

docker_daemon_ok() {
  need_cmd docker || return 1
  docker info >/dev/null 2>&1
}

ensure_docker_stack() {
  ensure_basic_tools

  # 1. 如果 docker 已经正常可用，直接用
  if docker_daemon_ok; then
    info "已检测到可用的 Docker 环境。"
  else
    # 2. 如果有 apt，并且是 Debian/Ubuntu，尽量用 apt 装 docker.io
    if need_cmd apt-get && [[ -f /etc/debian_version ]]; then
      warn "当前系统未检测到可用的 Docker，尝试通过 apt 安装 docker.io ..."
      apt_install docker.io 2>/dev/null || warn "通过 apt 安装 docker.io 失败，请稍后根据官方文档手动安装 Docker。"
      start_docker_daemon_soft
    else
      warn "系统未检测到 docker，可用包管理器也不是 apt，无法自动安装 Docker。"
    fi
  fi

  # 再检查一次
  if ! docker_daemon_ok; then
    cat <<EOF >&2
[!]
  无法检测到可用的 Docker 环境，脚本无法继续自动部署。

  建议你按以下步骤手动安装 Docker（任选一种方式）：
    1) 使用发行版自带包管理器安装（例如：apt-get install docker.io）
    2) 使用 Docker 官方文档安装 docker-ce：
       文档地址：https://docs.docker.com/engine/install/

  安装并确认 'docker info' 能正常运行后，再重新执行本脚本。
EOF
    exit 1
  fi

  # 只负责检测 compose，不再自动安装任何 compose 相关包
  if ! detect_compose; then
    cat <<EOF >&2
[!]
  已检测到 Docker，但未检测到 docker compose / docker-compose。

  请手动安装其中之一后再运行本脚本，例如（Debian/Ubuntu）：
    - apt-get install docker-compose
  或参考 Docker 官方文档安装 compose plugin。

  安装完成后，确保以下任意命令可以正常执行：
    - docker compose version
    - docker-compose version
EOF
    exit 1
  fi

  info "已选择使用 compose：${COMPOSE_KIND}"
}

gen_guid() {
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

# 检查端口是否被占用（TCP/UDP 任意）
is_port_in_use() {
  local port="$1"
  ss -tuln 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/.*://g' | grep -qx "$port"
}

# 在 10000-60000 区间内找一个未被使用的端口
random_free_port() {
  local p tries=0
  while :; do
    p=$(( RANDOM % 50001 + 10000 ))  # 10000~60000
    if ! is_port_in_use "$p"; then
      echo "$p"
      return 0
    fi
    tries=$((tries+1))
    if [[ "$tries" -gt 200 ]]; then
      die "在 10000-60000 区间内未能找到空闲端口，请检查当前端口占用情况。"
    fi
  done
}

# 返回 "LAN_IP|DEV|GW"
detect_net() {
  local out lan dev gw
  out="$(ip -4 route get 1.1.1.1 2>/dev/null || true)"
  lan="$(awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")"
  dev="$(awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")"
  gw="$(awk '/via/ {for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$out")"

  if [[ -z "$dev" ]]; then dev="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')" || true; fi
  if [[ -z "$gw"  ]]; then gw="$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')" || true; fi
  if [[ -z "$lan" ]]; then
    if [[ -n "${dev:-}" ]]; then
      lan="$(ip -4 addr show "$dev" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)" || true
    fi
  fi

  echo "${lan:-}|${dev:-}|${gw:-}"
}

download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"
  info "开始下载基准配置文件 appsettings.base.json ..."
  if ! curl_retry -sS "$url" -o appsettings.base.json; then
    die "下载基准配置失败，请检查 URL 或网络是否正常：$url"
  fi
}

enable_ip_forward_host() {
  info "尝试在宿主机开启 IPv4 转发（client 模式需要）..."
  if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
    cat >/etc/sysctl.d/99-openppp2.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null 2>&1 || true
  else
    warn "写入 sysctl 失败（可能权限受限或宿主不支持修改），client 模式可能无法正常转发。"
    warn "你可以手动执行：sysctl -w net.ipv4.ip_forward=1"
  fi
}

compose_header() {
  if [[ "$COMPOSE_KIND" == "docker-compose" ]]; then
    echo 'version: "3.8"'
  fi
}

write_compose_server() {
  local image="$1" cfg="$2"
  {
    compose_header
    cat <<EOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
EOF
  } >"$COMPOSE_FILE"
}

# 生成首个 client 服务（覆盖写 compose）
write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun_host="$6" tun_name="$7" tun_ip="$8" tun_gw="$9"

  {
    compose_header
    cat <<EOF
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
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
EOF

    if [[ "$tun_host" == "yes" ]]; then
      echo '      - "--tun-host"'
    fi

    cat <<EOF
      - "--tun=${tun_name}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
      - "--tun-mask=30"
      - "--tun-vnet=yes"
      - "--tun-flash=no"
      - "--tun-static=no"
      - "--block-quic=yes"
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
      - "--tun-mux=4"
      - "--tun-mux-acceleration=3"
      - "--tun-ssmt=4/st"
      - "--dns=8.8.8.8"
      - "--bypass-iplist-nic=${nic}"
      - "--bypass-iplist-ngw"
      - "${gw}"
EOF
  } >"$COMPOSE_FILE"
}

# 追加一个新的 client 服务（用于“新增 openppp2 客户端实例”）
append_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" ipfile="$6" dnsfile="$7" tun_host="$8" tun_name="$9" tun_ip="${10}" tun_gw="${11}"

  {
    cat <<EOF

  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
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
EOF

    if [[ "$tun_host" == "yes" ]]; then
      echo '      - "--tun-host"'
    fi

    cat <<EOF
      - "--tun=${tun_name}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
      - "--tun-mask=30"
      - "--tun-vnet=yes"
      - "--tun-flash=no"
      - "--tun-static=no"
      - "--block-quic=yes"
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
      - "--tun-mux=4"
      - "--tun-mux-acceleration=3"
      - "--tun-ssmt=4/st"
      - "--dns=8.8.8.8"
      - "--bypass-iplist-nic=${nic}"
      - "--bypass-iplist-ngw"
      - "${gw}"
EOF
  } >>"$COMPOSE_FILE"
}

setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "未检测到 systemd，无法配置 systemd 定时更新。你可以使用 crontab 定时执行 /usr/local/bin/ope

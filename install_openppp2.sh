#!/usr/bin/env bash
# =============================================================================
# openppp2-docker — One-click installer (fixed)
# Repo:    https://github.com/lucifer988/openppp2-docker
# Usage:   bash <(curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh)
# License: MIT
#
# v3.0.1 修复说明：
#   1) [严重] 修复客户端容器启动时 runc 报错：
#        sysctl "net.ipv4.ip_forward" not allowed in host network namespace
#      原因：network_mode: host 与 sysctls: net.ipv4.ip_forward 同时使用，
#            现代 runc 已经禁止从 host 网络命名空间内部修改 net.* sysctl。
#      修复：去掉 compose 中冗余的 sysctls: 块；IP 转发改在宿主机生效
#            （脚本本来就调用了 enable_ip_forward_host，原本就是冗余的）。
#   2) 修复 enable_ip_forward_host 写入后没有立即应用：增加 sysctl -w 显式应用。
#   3) ensure_tty_stdin 已定义但从未调用：在 main() 入口处调用，兼容 curl|bash。
#   4) USE_MUX 使用 prompt_yesno 进行 yes/no 归一化（之前是普通 prompt）。
#   5) ERR trap 增加常见故障提示，方便排错。
#   6) 其它若干健壮性改进。
# =============================================================================
set -Eeuo pipefail

# ----------------------------- 版本与默认配置 ------------------------------
readonly SCRIPT_VERSION="3.0.1"
readonly REPO_URL="https://github.com/lucifer988/openppp2-docker"
readonly RAW_BASE="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main"

# 工作目录
APP_DIR="${APP_DIR:-/opt/openppp2}"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
SECCOMP_FILE="${APP_DIR}/seccomp-openppp2.json"
BACKUP_DIR="${APP_DIR}/backups"
ROLE_FILE="${APP_DIR}/.role"
MAIN_SERVICE_FILE="${APP_DIR}/.client_main_service"

# 默认镜像
DEFAULT_IMAGE="${DEFAULT_IMAGE:-ghcr.io/lucifer988/openppp2:latest}"
DEFAULT_BASE_CFG_URL="${DEFAULT_BASE_CFG_URL:-${RAW_BASE}/appsettings.base.json}"

# systemd 自动更新（每周日凌晨 3 点）
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

# 默认/可被环境变量覆盖的参数
DEFAULT_CLIENT_NIC="${CLIENT_NIC:-}"
DEFAULT_BOOT_DELAY="${OPENPPP2_BOOT_DELAY:-20}"
STRICT_BOOT_DELAY_MODE="${STRICT_BOOT_DELAY_MODE:-no}"
NON_INTERACTIVE="${NON_INTERACTIVE:-no}"

# 运行时
COMPOSE_KIND=""  # "compose-plugin" 或 "docker-compose"

# ------------------------------ 终端与日志 -------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[1;33m'
  C_BLU=$'\033[0;34m'; C_BLD=$'\033[1m';     C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_BLD=""; C_RST=""
fi

log()  { printf '%s[*]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
info() { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YLW" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ERR trap：除了行号还给一些可能的原因，方便排错
on_err() {
  local ec=$? line=${1:-?}
  err "脚本第 ${line} 行异常退出（exit=${ec}）。"
  case "$ec" in
    1|125|126|127)
      err "常见原因："
      err "  · Docker 与宿主机配置冲突（例如 host 网络模式下设置 net.* sysctl，已在 v3.0.1 修复）"
      err "  · 拉取镜像失败：网络不通或镜像仓库无法访问，可尝试配置 HTTP 代理或镜像加速器"
      err "  · /dev/net/tun 不可用：需要宿主机内核支持 TUN（modprobe tun）"
      err "  · 容器名/端口冲突：已有 openppp2 容器在运行（docker ps -a | grep openppp2）"
      ;;
  esac
  err "如需协助请到 ${REPO_URL}/issues 反馈，并附上上述输出与 docker compose logs。"
  exit "$ec"
}
trap 'on_err $LINENO' ERR

# ------------------------------ 通用工具 ---------------------------------
need_cmd()    { command -v "$1" >/dev/null 2>&1; }
has_systemd() { [[ -d /run/systemd/system ]]; }

# 把 stdin 改回终端：当脚本通过 curl|bash 运行时，stdin 是管道，read 读不到
ensure_tty_stdin() {
  if [[ ! -t 0 ]] && [[ -e /dev/tty ]]; then
    exec </dev/tty
  fi
}

prompt() {
  local _p_var="$1" _p_msg="$2" _p_def="${3:-}" _p_ans=""
  if [[ "${NON_INTERACTIVE:-no}" == "yes" ]]; then
    printf -v "$_p_var" '%s' "$_p_def"
    info "[非交互] ${_p_msg} → ${_p_def}"
    return 0
  fi
  if [[ -n "$_p_def" ]]; then
    read -r -p "${_p_msg} [${_p_def}]: " _p_ans || true
    _p_ans="${_p_ans:-$_p_def}"
  else
    read -r -p "${_p_msg}: " _p_ans || true
  fi
  printf -v "$_p_var" '%s' "$_p_ans"
}

prompt_yesno() {
  local _py_var="$1" _py_msg="$2" _py_def="${3:-no}" _py_ans=""
  while true; do
    prompt _py_ans "$_py_msg (yes/no)" "$_py_def"
    case "${_py_ans,,}" in
      y|yes) printf -v "$_py_var" '%s' "yes"; return 0 ;;
      n|no)  printf -v "$_py_var" '%s' "no";  return 0 ;;
      *) warn "请输入 yes 或 no。" ;;
    esac
  done
}

prompt_port() {
  local _pp_var="$1" _pp_msg="$2" _pp_def="${3:-}" _pp_ans=""
  while true; do
    prompt _pp_ans "$_pp_msg" "$_pp_def"
    if [[ "$_pp_ans" =~ ^[0-9]+$ ]] && (( _pp_ans >= 1 && _pp_ans <= 65535 )); then
      printf -v "$_pp_var" '%s' "$_pp_ans"
      return 0
    fi
    warn "端口必须是 1-65535 之间的整数。"
  done
}

prompt_ip() {
  local _pi_var="$1" _pi_msg="$2" _pi_def="${3:-}" _pi_ans=""
  while true; do
    prompt _pi_ans "$_pi_msg" "$_pi_def"
    if [[ "$_pi_ans" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      local _pi_ok=1 _pi_oct
      local -a _pi_octs
      IFS='.' read -r -a _pi_octs <<<"$_pi_ans"
      for _pi_oct in "${_pi_octs[@]}"; do (( _pi_oct <= 255 )) || _pi_ok=0; done
      if (( _pi_ok )); then printf -v "$_pi_var" '%s' "$_pi_ans"; return 0; fi
    fi
    warn "请输入合法的 IPv4 地址（例如 1.2.3.4）。"
  done
}

gen_guid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    printf '{%s}' "$(tr 'a-z' 'A-Z' < /proc/sys/kernel/random/uuid)"
  elif need_cmd uuidgen; then
    printf '{%s}' "$(uuidgen | tr 'a-z' 'A-Z')"
  else
    printf '{%08X-%04X-%04X-%04X-%012X}' \
      "$((RANDOM*RANDOM))" "$RANDOM" "$RANDOM" "$RANDOM" "$((RANDOM*RANDOM*RANDOM))"
  fi
}

curl_retry() {
  local tries=0 max=3
  while (( tries < max )); do
    if curl --fail --silent --show-error --location --max-time 30 "$@"; then return 0; fi
    tries=$((tries+1))
    sleep 2
  done
  return 1
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "请以 root 身份运行（或使用 sudo）。"
  fi
}

# ------------------------------- 环境检测 --------------------------------
check_env_supported() {
  case "$(uname -s)" in
    Linux) ;;
    *) die "仅支持 Linux。当前：$(uname -s)。" ;;
  esac
  if [[ "$(uname -m)" != "x86_64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
    warn "当前架构 $(uname -m) 未经充分测试。"
  fi
  local kver
  kver="$(uname -r | cut -d. -f1-2)"
  local maj min
  maj="${kver%%.*}"; min="${kver##*.}"
  if (( maj < 5 )) || { (( maj == 5 )) && (( min < 1 )); }; then
    warn "内核 ${kver} < 5.1，io_uring 可能不支持，建议升级内核。"
  fi
}

detect_distro() {
  if [[ -f /etc/os-release ]]; then . /etc/os-release; echo "${ID:-unknown}"; else echo "unknown"; fi
}

# ------------------------------- 依赖安装 --------------------------------
install_basic_deps() {
  local missing=()
  for c in curl jq; do
    need_cmd "$c" || missing+=("$c")
  done
  (( ${#missing[@]} == 0 )) && return 0

  local distro; distro="$(detect_distro)"
  case "$distro" in
    debian|ubuntu)
      info "安装基础依赖：${missing[*]}"
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" ca-certificates
      ;;
    centos|rhel|rocky|almalinux|fedora)
      info "安装基础依赖：${missing[*]}"
      if need_cmd dnf; then dnf install -y "${missing[@]}" ca-certificates
      else yum install -y "${missing[@]}" ca-certificates; fi
      ;;
    *)
      die "未能识别发行版 ${distro}，请手动安装：${missing[*]}"
      ;;
  esac
}

install_docker() {
  if need_cmd docker; then
    info "Docker 已安装：$(docker --version)"
    return 0
  fi
  info "未检测到 Docker，正在安装..."
  if ! curl_retry https://get.docker.com -o /tmp/get-docker.sh; then
    die "下载 Docker 安装脚本失败。"
  fi
  sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  if has_systemd; then
    systemctl enable --now docker
  fi
  need_cmd docker || die "Docker 安装失败。"
  info "Docker 安装完成：$(docker --version)"
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="compose-plugin"
    return 0
  fi
  if need_cmd docker-compose; then
    COMPOSE_KIND="docker-compose"
    return 0
  fi
  # 尝试通过包管理器装 compose 插件
  local distro; distro="$(detect_distro)"
  case "$distro" in
    debian|ubuntu)
      info "安装 docker-compose-plugin..."
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin || true
      ;;
    centos|rhel|rocky|almalinux|fedora)
      info "安装 docker-compose-plugin..."
      if need_cmd dnf; then dnf install -y docker-compose-plugin || true
      else yum install -y docker-compose-plugin || true; fi
      ;;
  esac
  if docker compose version >/dev/null 2>&1; then COMPOSE_KIND="compose-plugin"; return 0; fi
  if need_cmd docker-compose; then COMPOSE_KIND="docker-compose"; return 0; fi
  die "未能找到 docker compose（v2 插件）或 docker-compose（v1）。"
}

compose() {
  case "$COMPOSE_KIND" in
    compose-plugin) docker compose "$@" ;;
    docker-compose) docker-compose "$@" ;;
    *) die "compose 命令未初始化。" ;;
  esac
}

# 轻量级 compose 探测：只检测当前已安装的，不会主动安装。
ensure_compose_detected() {
  [[ -n "$COMPOSE_KIND" ]] && return 0
  if docker compose version >/dev/null 2>&1; then COMPOSE_KIND="compose-plugin"; return 0; fi
  if need_cmd docker-compose; then COMPOSE_KIND="docker-compose"; return 0; fi
  die "未检测到 docker compose / docker-compose。请先执行安装（菜单 1）。"
}

ensure_stack_ready() {
  install_basic_deps
  install_docker
  detect_compose
  mkdir -p "$APP_DIR" "$BACKUP_DIR"
}

# ------------------------------ 网络相关 ---------------------------------
port_in_use() {
  local p="$1"
  if need_cmd ss; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$" && return 0
    ss -lun 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${p}\$" && return 0
  elif need_cmd netstat; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$" && return 0
    netstat -lun 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$" && return 0
  fi
  return 1
}

random_free_port() {
  local p tries=0
  while (( tries < 200 )); do
    p=$(( (RANDOM % 50000) + 10000 ))
    if ! port_in_use "$p"; then echo "$p"; return 0; fi
    tries=$((tries+1))
  done
  die "找不到空闲端口。"
}

detect_net() {
  local nic="" gw="" ip=""
  if need_cmd ip; then
    nic="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    gw="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $3; exit}')"
    if [[ -n "$nic" ]]; then
      ip="$(ip -4 -o addr show dev "$nic" 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"
    fi
  fi
  printf '%s|%s|%s' "$ip" "$nic" "$gw"
}

# 在宿主机层面启用 IP 转发；客户端运行在 host 网络模式时必须由宿主机提供
# 注意：由于 runc 禁止 host 网络模式下设置 net.* sysctl，
# 我们绝对不能把 sysctls: 块写到 docker-compose.yml 里，必须在这里设置好。
enable_ip_forward_host() {
  local f=/etc/sysctl.d/99-openppp2.conf
  cat >"$f" <<'EOF'
# Managed by openppp2-docker installer
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  # 立即应用（不等系统重启或 --system 全量重载）
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
  # 再做一次全量重载，确保配置持久化
  sysctl --system >/dev/null 2>&1 || true

  # 校验
  local v4 v6
  v4="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
  v6="$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)"
  if [[ "$v4" != "1" ]]; then
    warn "宿主机 net.ipv4.ip_forward 当前值为 ${v4}，未能启用 IPv4 转发，可能影响客户端路由功能。"
  else
    info "宿主机 IPv4 转发已启用（net.ipv4.ip_forward=1）。"
  fi
  if [[ "$v6" != "1" ]]; then
    info "宿主机 net.ipv6.conf.all.forwarding=${v6}（IPv6 转发未启用；通常无影响）。"
  fi
}

# ----------------------------- seccomp 配置 ------------------------------
# openppp2 用到了 io_uring；默认 seccomp 拒绝 io_uring_*。
# 这里基于 docker 默认 profile 思想，只放开必要系统调用。
generate_seccomp_profile() {
  local out="$1"
  cat >"$out" <<'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "syscalls": [
    {
      "names": [
        "accept","accept4","access","arch_prctl","bind","brk","capget","capset",
        "chdir","chmod","chown","clock_getres","clock_gettime","clock_nanosleep",
        "clone","clone3","close","close_range","connect","copy_file_range",
        "creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl",
        "epoll_pwait","epoll_pwait2","epoll_wait","eventfd","eventfd2","execve",
        "execveat","exit","exit_group","faccessat","faccessat2","fadvise64",
        "fallocate","fchdir","fchmod","fchmodat","fchown","fchownat","fcntl",
        "fdatasync","flistxattr","flock","fork","fremovexattr","fsetxattr",
        "fstat","fstatfs","fsync","ftruncate","futex","futex_waitv","getcpu",
        "getcwd","getdents","getdents64","getegid","geteuid","getgid","getgroups",
        "getitimer","getpeername","getpgid","getpgrp","getpid","getppid",
        "getpriority","getrandom","getresgid","getresuid","getrlimit","getrusage",
        "getsid","getsockname","getsockopt","gettid","gettimeofday","getuid",
        "getxattr","inotify_add_watch","inotify_init","inotify_init1",
        "inotify_rm_watch","io_cancel","io_destroy","io_getevents","io_pgetevents",
        "io_setup","io_submit","io_uring_enter","io_uring_register","io_uring_setup",
        "ioctl","ioprio_get","ioprio_set","ipc","kill","landlock_add_rule",
        "landlock_create_ruleset","landlock_restrict_self","lgetxattr","link",
        "linkat","listen","listxattr","llistxattr","lremovexattr","lseek",
        "lsetxattr","lstat","madvise","mbind","membarrier","memfd_create",
        "mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall",
        "mmap","mount_setattr","mprotect","mq_getsetattr","mq_notify","mq_open",
        "mq_timedreceive","mq_timedsend","mq_unlink","mremap","msgctl","msgget",
        "msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at",
        "nanosleep","newfstatat","open","openat","openat2","pause","pidfd_open",
        "pidfd_send_signal","pipe","pipe2","poll","ppoll","prctl","pread64",
        "preadv","preadv2","prlimit64","process_mrelease","pselect6","pwrite64",
        "pwritev","pwritev2","read","readahead","readlink","readlinkat","readv",
        "recv","recvfrom","recvmmsg","recvmsg","remap_file_pages","removexattr",
        "rename","renameat","renameat2","restart_syscall","rmdir","rseq",
        "rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo",
        "rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_tgsigqueueinfo",
        "sched_get_priority_max","sched_get_priority_min","sched_getaffinity",
        "sched_getattr","sched_getparam","sched_getscheduler","sched_rr_get_interval",
        "sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler",
        "sched_yield","seccomp","select","semctl","semget","semop","semtimedop",
        "send","sendfile","sendmmsg","sendmsg","sendto","setfsgid","setfsuid",
        "setgid","setgroups","setitimer","setpgid","setpriority","setregid",
        "setresgid","setresuid","setreuid","setrlimit","setsid","setsockopt",
        "setuid","setxattr","shmat","shmctl","shmdt","shmget","shutdown",
        "sigaltstack","signalfd","signalfd4","socket","socketcall","socketpair",
        "splice","stat","statfs","statx","symlink","symlinkat","sync","sync_file_range",
        "syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete",
        "timer_getoverrun","timer_gettime","timer_settime","timerfd_create",
        "timerfd_gettime","timerfd_settime","times","tkill","truncate","ugetrlimit",
        "umask","uname","unlink","unlinkat","utime","utimensat","utimes","vfork",
        "vmsplice","wait4","waitid","waitpid","write","writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{ "index": 0, "value": 0, "op": "SCMP_CMP_EQ" }]
    }
  ]
}
EOF
}

# --------------------------- 基础配置文件下载 -----------------------------
EMBEDDED_BASE_CFG='{
  "concurrent": 4,
  "cdn": [],
  "key": {
    "kf": 154543927, "kx": 128, "kl": 10, "kh": 12, "sb": 1000,
    "protocol": "simd-aes-128-cfb", "protocol-key": "N6HMzdUs7IUnYHwqA",
    "transport": "simd-aes-256-cfb", "transport-key": "HWFweXu2g5RVMEpyA",
    "masked": false, "plaintext": false, "delta-encode": false, "shuffle-data": false
  },
  "ip": { "public": "192.168.0.24", "interface": "192.168.0.24" },
  "vmem": { "size": 4096, "path": "./{}" },
  "tcp": {
    "inactive": { "timeout": 300 },
    "connect": { "timeout": 5, "nexcept": 4 },
    "listen": { "port": 20000 },
    "cwnd": 0, "rwnd": 0, "turbo": true, "backlog": 511, "fast-open": true
  },
  "udp": {
    "cwnd": 0, "rwnd": 0,
    "inactive": { "timeout": 72 },
    "dns": { "timeout": 4, "ttl": 60, "cache": true, "turbo": true, "redirect": "0.0.0.0" },
    "listen": { "port": 20000 },
    "static": { "keep-alived": [20, 60], "dns": true, "quic": true, "icmp": true, "aggligator": 0, "servers": [] }
  },
  "mux": {
    "connect": { "timeout": 20 },
    "inactive": { "timeout": 60 },
    "congestions": 134217728,
    "keep-alived": [5, 20]
  },
  "websocket": {
    "host": "starrylink.net", "path": "/tun",
    "listen": {},
    "ssl": {
      "certificate-file": "starrylink.net.pem",
      "certificate-chain-file": "starrylink.net.pem",
      "certificate-key-file": "starrylink.net.key",
      "certificate-key-password": "test",
      "ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    },
    "verify-peer": true,
    "http": {
      "error": "Status Code: 404; Not Found",
      "request": {
        "Cache-Control": "no-cache", "Pragma": "no-cache",
        "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "http://www.websocket-test.com",
        "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
      },
      "response": { "Server": "Kestrel" }
    }
  },
  "server": {
    "log": "./ppp.log", "node": 1, "subnet": true, "mapping": true,
    "backend": "", "backend-key": ""
  },
  "client": {
    "guid": "{F4569208-BB45-4DEB-B115-0FEA1D91B85B}",
    "server": "ppp://192.168.0.24:20000/",
    "server-proxy": "",
    "bandwidth": 0,
    "reconnections": { "timeout": 5 },
    "paper-airplane": { "tcp": true },
    "http-proxy": { "bind": "192.168.0.24", "port": 8080 },
    "socks-proxy": { "bind": "192.168.0.24", "port": 1080, "username": "test", "password": "123456" },
    "mappings": [],
    "routes": []
  }
}'

download_base_cfg() {
  local url="$1" out="${APP_DIR}/appsettings.base.json"
  if curl_retry "$url" -o "$out.tmp" 2>/dev/null; then
    if jq empty "$out.tmp" 2>/dev/null; then
      mv "$out.tmp" "$out"
      info "已下载基准配置：${url}"
      return 0
    else
      warn "下载到的配置文件不是合法 JSON，使用内置基准配置。"
      rm -f "$out.tmp"
    fi
  else
    warn "下载基准配置失败，使用内置基准配置。"
  fi
  printf '%s' "$EMBEDDED_BASE_CFG" >"$out"
  jq empty "$out" || die "内置基准配置异常。"
}

# ----------------------------- compose 写入 ------------------------------
write_compose_server() {
  local image="$1" cfg_file="$2"
  cat >"$COMPOSE_FILE" <<EOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
    security_opt:
      - seccomp=${SECCOMP_FILE}
    volumes:
      - ${APP_DIR}/${cfg_file}:/opt/openppp2/appsettings.json:ro
    command: ["--mode=server", "--config=./appsettings.json"]
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
}

# 写入主客户端服务块（Compose 服务名 = 容器名）
# 注意（v3.0.1 修复）：
#   - 不再写入 sysctls: 块。原因：network_mode: host 与 net.* sysctl 互斥，
#     现代 runc 会直接拒绝（OCI runtime create failed）。
#   - IP 转发改由宿主机层面的 enable_ip_forward_host 完成（脚本会自动调用）。
write_compose_client() {
  local image="$1" nic="$2" gw="$3" service="$4" cfg_file="$5"
  local tun="$6" tun_ip="$7" tun_gw="$8" use_mux="$9"
  cat >"$COMPOSE_FILE" <<EOF
services:
  ${service}:
    image: ${image}
    container_name: ${service}
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    security_opt:
      - seccomp=${SECCOMP_FILE}
    volumes:
      - ${APP_DIR}/${cfg_file}:/opt/openppp2/appsettings.json:ro
      - ${APP_DIR}/ip.txt:/opt/openppp2/ip.txt:ro
      - ${APP_DIR}/dns-rules.txt:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=./appsettings.json"
      - "--tun=${tun}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
      - "--tun-host=no"
      - "--nic=${nic}"
      - "--ngw=${gw}"
EOF
  if [[ "$use_mux" == "yes" ]]; then
    printf '      - "--mux=on"\n' >>"$COMPOSE_FILE"
  fi
  cat >>"$COMPOSE_FILE" <<EOF
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
}

# 在已有的 client compose 上追加一个新的实例（注意：同样不写 sysctls:）
append_compose_client() {
  local image="$1" nic="$2" gw="$3" service="$4" cfg_file="$5"
  local tun="$6" tun_ip="$7" tun_gw="$8" use_mux="$9"
  cat >>"$COMPOSE_FILE" <<EOF
  ${service}:
    image: ${image}
    container_name: ${service}
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    security_opt:
      - seccomp=${SECCOMP_FILE}
    volumes:
      - ${APP_DIR}/${cfg_file}:/opt/openppp2/appsettings.json:ro
      - ${APP_DIR}/ip.txt:/opt/openppp2/ip.txt:ro
      - ${APP_DIR}/dns-rules.txt:/opt/openppp2/dns-rules.txt:ro
    command:
      - "--mode=client"
      - "--config=./appsettings.json"
      - "--tun=${tun}"
      - "--tun-ip=${tun_ip}"
      - "--tun-gw=${tun_gw}"
      - "--tun-host=no"
      - "--nic=${nic}"
      - "--ngw=${gw}"
EOF
  if [[ "$use_mux" == "yes" ]]; then
    printf '      - "--mux=on"\n' >>"$COMPOSE_FILE"
  fi
  cat >>"$COMPOSE_FILE" <<EOF
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
}

# 删除 compose 中指定服务（粗暴但够用：按服务名块定位）
remove_compose_service() {
  local service="$1"
  [[ -f "$COMPOSE_FILE" ]] || return 0
  python3 - "$COMPOSE_FILE" "$service" <<'PY' 2>/dev/null || awk_remove_service "$service"
import sys, re
fp, svc = sys.argv[1], sys.argv[2]
with open(fp, 'r', encoding='utf-8') as f:
    lines = f.readlines()
out = []; skip = False
for ln in lines:
    if re.match(r'^\s{2}'+re.escape(svc)+r':\s*$', ln):
        skip = True; continue
    if skip:
        if ln.startswith('  ') and not ln.startswith('    '):
            if re.match(r'^\s{2}[A-Za-z0-9_-]+:\s*$', ln):
                skip = False; out.append(ln); continue
            else:
                continue
        elif ln.startswith(' '):
            continue
        else:
            skip = False
    out.append(ln)
open(fp, 'w', encoding='utf-8').writelines(out)
PY
}

awk_remove_service() {
  local service="$1" tmp
  tmp="$(mktemp)"
  awk -v svc="$service" '
    BEGIN { skip=0 }
    {
      if (match($0, "^  " svc ":[[:space:]]*$")) { skip=1; next }
      if (skip) {
        if (match($0, "^  [A-Za-z0-9_-]+:[[:space:]]*$")) { skip=0; print; next }
        if (match($0, "^[[:space:]]")) { next }
        skip=0
      }
      print
    }
  ' "$COMPOSE_FILE" >"$tmp" && mv "$tmp" "$COMPOSE_FILE"
}

# -------------------------- Docker 拉取代理（可选） -------------------------
DOCKER_PROXY_DROPIN="/etc/systemd/system/docker.service.d/http-proxy.conf"

setup_docker_proxy() {
  local ip="$1" port="$2"
  has_systemd || { warn "无 systemd，跳过 Docker 代理配置。"; return 1; }
  mkdir -p "$(dirname "$DOCKER_PROXY_DROPIN")"
  cat >"$DOCKER_PROXY_DROPIN" <<EOF
[Service]
Environment="HTTP_PROXY=http://${ip}:${port}"
Environment="HTTPS_PROXY=http://${ip}:${port}"
Environment="NO_PROXY=localhost,127.0.0.1,::1"
EOF
  systemctl daemon-reload
  systemctl restart docker
  info "Docker HTTP 代理已临时配置为 http://${ip}:${port}"
  return 0
}

cleanup_docker_proxy_after_pull() {
  local was_set="$1"
  [[ "$was_set" -eq 1 ]] || return 0
  rm -f "$DOCKER_PROXY_DROPIN"
  # 故意不立刻重启 docker，避免把刚拉起来的容器顺手停掉
}

remove_docker_proxy() {
  if [[ -f "$DOCKER_PROXY_DROPIN" ]]; then
    rm -f "$DOCKER_PROXY_DROPIN"
    if has_systemd; then
      systemctl daemon-reload || true
    fi
  fi
}

# -------------------------------- 健康检查 -------------------------------
health_check_one() {
  local svc="$1" tries=0 max=30
  while (( tries < max )); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "$svc" 2>/dev/null)" == "true" ]]; then
      info "容器 ${svc} 正在运行。"
      return 0
    fi
    sleep 1
    tries=$((tries+1))
  done
  warn "容器 ${svc} 在 ${max}s 内未进入 Running 状态，请查看日志。"
  return 1
}

# ----------------------------- systemd 自动更新 --------------------------
setup_systemd_weekly_update() {
  has_systemd || return 0
  cat >/usr/local/bin/openppp2-update.sh <<'EOF'
#!/usr/bin/env bash
set -e
cd /opt/openppp2 || exit 1
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  docker compose pull
  docker compose up -d --remove-orphans
elif command -v docker-compose >/dev/null; then
  docker-compose pull
  docker-compose up -d --remove-orphans
fi
EOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'EOF'
[Unit]
Description=openppp2 weekly update
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
EOF

  cat >/etc/systemd/system/openppp2-update.timer <<EOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${DEFAULT_ONCAL}
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer
  info "已启用 systemd 每周自动更新（${DEFAULT_ONCAL}）。"
}

# -------------------------------- 备份/恢复 ------------------------------
do_backup() {
  require_root
  [[ -d "$APP_DIR" ]] || die "未找到 ${APP_DIR}，请先安装。"
  mkdir -p "$BACKUP_DIR"
  local ts dest
  ts="$(date +%Y%m%d_%H%M%S)"
  dest="${BACKUP_DIR}/backup_${ts}"
  mkdir -p "$dest"
  shopt -s nullglob
  for f in "$APP_DIR"/appsettings*.json "$COMPOSE_FILE" "$SECCOMP_FILE" "$ROLE_FILE" "$MAIN_SERVICE_FILE"; do
    [[ -f "$f" ]] && cp -a "$f" "$dest/"
  done
  shopt -u nullglob
  info "已备份至 ${dest}"
}

do_restore() {
  require_root
  [[ -d "$BACKUP_DIR" ]] || die "没有可用备份目录。"
  local latest
  latest="$(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup_*' | sort | tail -1)"
  [[ -n "$latest" ]] || die "没有找到任何备份。"
  info "从 ${latest} 恢复..."
  cp -a "$latest"/. "$APP_DIR"/
  info "已恢复。请运行 'cd ${APP_DIR} && docker compose up -d --remove-orphans' 应用变更。"
}

# -------------------------------- 客户端管理 -----------------------------
do_show_info() {
  [[ -f "$COMPOSE_FILE" ]] || die "未发现 ${COMPOSE_FILE}。"
  ensure_compose_detected
  local role; role="$(cat "$ROLE_FILE" 2>/dev/null || echo unknown)"
  echo "角色：${role}"
  echo "目录：${APP_DIR}"
  echo "----- 容器 -----"
  (cd "$APP_DIR" && compose ps) || true
  echo
  shopt -s nullglob
  for cfg in "$APP_DIR"/appsettings*.json; do
    [[ "$(basename "$cfg")" == "appsettings.base.json" ]] && continue
    echo "===== $(basename "$cfg") ====="
    if need_cmd jq; then
      jq '{server: .client.server,
           http_bind: .client["http-proxy"].bind, http_port: .client["http-proxy"].port,
           socks_bind: .client["socks-proxy"].bind, socks_port: .client["socks-proxy"].port,
           socks_user: .client["socks-proxy"].username,
           socks_pass: .client["socks-proxy"].password}' "$cfg" || cat "$cfg"
    else
      cat "$cfg"
    fi
    echo
  done
  shopt -u nullglob
}

list_client_services() {
  [[ -f "$COMPOSE_FILE" ]] || return 1
  awk '/^  [A-Za-z0-9_-]+:[[:space:]]*$/ { gsub(/:/,"",$1); print $1 }' "$COMPOSE_FILE"
}

do_add_client() {
  require_root
  [[ -f "$COMPOSE_FILE" ]] || die "请先完成主安装。"
  [[ "$(cat "$ROLE_FILE" 2>/dev/null)" == "client" ]] || die "当前不是 client 角色。"
  [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在。"
  ensure_compose_detected

  local svc cfg n=2
  while :; do
    svc="openppp2-${n}"
    cfg="appsettings-openppp2-${n}.json"
    if ! list_client_services | grep -qx "$svc"; then break; fi
    n=$((n+1))
  done

  local SERVER_IP SERVER_PORT
  prompt_ip   SERVER_IP   "服务端 IP" ""
  prompt_port SERVER_PORT "服务端端口" "20000"

  local netinfo lan nic gw
  netinfo="$(detect_net)"
  lan="${netinfo%%|*}"; netinfo="${netinfo#*|}"
  nic="${netinfo%%|*}"; gw="${netinfo#*|}"
  [[ -n "$lan" ]] || prompt    lan "客户端内网 IP" ""
  [[ -n "$nic" ]] || prompt    nic "默认网卡名" ""
  [[ -n "$gw"  ]] || prompt_ip gw  "默认网关 IP" ""

  local guid; guid="$(gen_guid)"
  local HTTP_PORT SOCKS_PORT
  HTTP_PORT="$(random_free_port)"
  SOCKS_PORT="$(random_free_port)"
  while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do SOCKS_PORT="$(random_free_port)"; done

  jq --arg srv "ppp://${SERVER_IP}:${SERVER_PORT}/" \
     --arg guid "$guid" \
     --arg lan "$lan" \
     --argjson hport "$HTTP_PORT" \
     --argjson sport "$SOCKS_PORT" \
     '.client.server=$srv | .client.guid=$guid
      | .client["http-proxy"].bind=$lan | .client["http-proxy"].port=$hport
      | .client["socks-proxy"].bind=$lan | .client["socks-proxy"].port=$sport' \
     "${APP_DIR}/appsettings.base.json" >"${APP_DIR}/${cfg}"

  local tun="ppp${n}" tun_ip="10.0.${n}.2" tun_gw="10.0.${n}.1"
  append_compose_client "$DEFAULT_IMAGE" "$nic" "$gw" "$svc" "$cfg" "$tun" "$tun_ip" "$tun_gw" "no"
  (cd "$APP_DIR" && compose up -d --remove-orphans "$svc")
  info "新增客户端实例：${svc}（HTTP=${lan}:${HTTP_PORT}，SOCKS5=${lan}:${SOCKS_PORT}）"
}

do_delete_client() {
  require_root
  [[ -f "$COMPOSE_FILE" ]] || die "未发现 ${COMPOSE_FILE}。"
  ensure_compose_detected

  local services=()
  mapfile -t services < <(list_client_services)
  (( ${#services[@]} > 0 )) || die "没有可删除的服务。"

  echo "现有服务："
  local i=0
  for s in "${services[@]}"; do i=$((i+1)); echo "  ${i}) ${s}"; done

  local pick svc
  prompt pick "选择要删除的服务编号" ""
  [[ "$pick" =~ ^[0-9]+$ ]] || die "请输入数字。"
  (( pick >= 1 && pick <= ${#services[@]} )) || die "编号越界。"
  svc="${services[$((pick-1))]}"

  if [[ "$svc" == "openppp2" ]]; then
    warn "你选择删除的是主服务 openppp2，将导致整体服务停止。"
    local CONF; prompt_yesno CONF "确认删除主服务？" "no"
    [[ "$CONF" == "yes" ]] || { info "已取消。"; return 0; }
  fi

  (cd "$APP_DIR" && compose rm -fs "$svc") || true
  remove_compose_service "$svc"
  # 同步删除对应的 appsettings 文件
  local cfg="appsettings-${svc}.json"
  [[ -f "${APP_DIR}/${cfg}" ]] && rm -f "${APP_DIR}/${cfg}"
  info "已删除服务 ${svc}。"
}

# ------------------------------- 安装/卸载 ------------------------------
do_install() {
  require_root
  ensure_stack_ready

  echo "=============================="
  echo "  请选择安装/部署角色："
  echo "    1) 服务端（Server）"
  echo "    2) 客户端（Client）"
  echo "=============================="
  local ROLE; prompt ROLE "请输入数字（1 或 2）" "1"
  [[ "$ROLE" == "1" || "$ROLE" == "2" ]] || die "角色选择错误。"

  local IMAGE BASE_URL
  prompt IMAGE   "请输入镜像地址"          "$DEFAULT_IMAGE"
  prompt BASE_URL "请输入基准配置文件 URL" "$DEFAULT_BASE_CFG_URL"

  download_base_cfg "$BASE_URL"
  generate_seccomp_profile "$SECCOMP_FILE"

  local proxy_configured=0 proxy_cleanup_deferred=0

  if [[ "$ROLE" == "1" ]]; then
    # ---------- 服务端 ----------
    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的服务端配置文件名" "appsettings.json"

    local autoip="" SERVER_PUBLIC_IP SERVER_BIND_IP
    autoip="$(curl_retry https://api.ipify.org 2>/dev/null || true)"
    prompt_ip SERVER_PUBLIC_IP "服务端对外（公网）IP" "${autoip:-}"
    prompt_ip SERVER_BIND_IP   "服务端监听 bind IP（NAT 填内网；直连填公网）" "$SERVER_PUBLIC_IP"

    jq --arg ip "$SERVER_PUBLIC_IP" --arg bind "$SERVER_BIND_IP" \
       '.ip.public=$ip | .ip.interface=$bind' \
       "${APP_DIR}/appsettings.base.json" >"${APP_DIR}/${APP_CFG_NAME}"

    write_compose_server "$IMAGE" "$APP_CFG_NAME"
    echo "server" >"$ROLE_FILE"

  else
    # ---------- 客户端 ----------
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在，宿主机不支持 TUN。"

    local APP_CFG_NAME MAIN_SERVICE_NAME
    prompt APP_CFG_NAME       "请输入要生成的客户端配置文件名" "appsettings.json"
    prompt MAIN_SERVICE_NAME  "主客户端实例名称（容器/服务名）" "openppp2"

    local SERVER_IP SERVER_PORT
    prompt_ip   SERVER_IP   "服务端 IP"   ""
    prompt_port SERVER_PORT "服务端端口" "20000"

    local netinfo lan nic gw
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"; netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"; gw="${netinfo#*|}"

    if [[ -n "$DEFAULT_CLIENT_NIC" ]]; then
      nic="$DEFAULT_CLIENT_NIC"
      info "使用环境变量指定网卡：${nic}"
    fi

    if [[ -z "$lan" || "$lan" =~ ^10\. ]]; then
      warn "未检测到合适的内网 IP，请手动输入。"
      prompt lan "客户端内网 IP（用于 http/socks bind）" ""
    else
      info "检测到内网 IP：${lan}"
    fi
    if [[ -z "$nic" ]]; then
      prompt nic "默认网卡名" ""
    else
      info "检测到默认网卡：${nic}"
    fi
    if [[ -z "$gw" ]]; then
      prompt_ip gw "默认网关 IP" ""
    else
      info "检测到默认网关：${gw}"
    fi

    local guid; guid="$(gen_guid)"
    local HTTP_PORT SOCKS_PORT
    HTTP_PORT="$(random_free_port)"
    SOCKS_PORT="$(random_free_port)"
    while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do SOCKS_PORT="$(random_free_port)"; done

    jq --arg srv "ppp://${SERVER_IP}:${SERVER_PORT}/" \
       --arg guid "$guid" \
       --arg lan "$lan" \
       --argjson hport "$HTTP_PORT" \
       --argjson sport "$SOCKS_PORT" \
       '.client.server=$srv | .client.guid=$guid
        | .client["http-proxy"].bind=$lan | .client["http-proxy"].port=$hport
        | .client["socks-proxy"].bind=$lan | .client["socks-proxy"].port=$sport' \
       "${APP_DIR}/appsettings.base.json" >"${APP_DIR}/${APP_CFG_NAME}"

    : >"${APP_DIR}/ip.txt"
    : >"${APP_DIR}/dns-rules.txt"

    enable_ip_forward_host

    local USE_MUX
    prompt_yesno USE_MUX "是否开启 mux？" "no"
    write_compose_client "$IMAGE" "$nic" "$gw" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME" \
                          "ppp0" "10.0.0.2" "10.0.0.1" "$USE_MUX"

    echo "client" >"$ROLE_FILE"
    echo "$MAIN_SERVICE_NAME" >"$MAIN_SERVICE_FILE"

    echo
    echo "客户端配置摘要："
    echo "  配置文件：${APP_CFG_NAME}"
    echo "  server  ：ppp://${SERVER_IP}:${SERVER_PORT}/"
    echo "  HTTP    ：${lan}:${HTTP_PORT}"
    echo "  SOCKS5  ：${lan}:${SOCKS_PORT}"

    echo
    local USE_PROXY
    prompt_yesno USE_PROXY "是否需要为 Docker 配置 HTTP 代理来拉取镜像？" "no"

    if [[ "$USE_PROXY" == "yes" ]]; then
      local PROXY_IP PROXY_PORT
      prompt_ip   PROXY_IP   "代理服务器 IP" ""
      prompt_port PROXY_PORT "代理服务器端口" "7890"
      if setup_docker_proxy "$PROXY_IP" "$PROXY_PORT"; then
        proxy_configured=1
      else
        warn "代理配置失败，将不使用代理继续。"
      fi
    fi
  fi

  echo
  info "预拉取镜像..."
  (cd "$APP_DIR" && compose pull) || warn "镜像预拉取失败，稍后 up 时再次尝试。"

  if [[ "$ROLE" == "2" ]]; then
    cleanup_docker_proxy_after_pull "$proxy_configured"
    if [[ "$proxy_configured" -eq 1 ]]; then
      proxy_cleanup_deferred=1
      info "已完成镜像拉取，Docker 代理配置文件已删除（暂未重启 daemon，避免误杀新容器）。"
    fi
  fi

  echo
  info "启动 openppp2..."
  (cd "$APP_DIR" && compose up -d --remove-orphans)

  if [[ "$ROLE" == "2" ]]; then
    health_check_one "$(cat "${APP_DIR}/.client_main_service" 2>/dev/null || echo openppp2)" \
      || warn "健康检查未通过，请用 'docker logs <容器名>' 查看具体错误。"
  else
    health_check_one "openppp2" \
      || warn "健康检查未通过，请用 'docker logs openppp2' 查看具体错误。"
  fi

  setup_systemd_weekly_update

  if [[ "$ROLE" == "2" && "$proxy_cleanup_deferred" -eq 1 ]]; then
    echo
    warn "注意：Docker 代理配置文件已删除，但当前 Docker daemon 尚未重启。"
    warn "如果你后续需要让 Docker 完全丢弃旧代理，请手动执行：systemctl restart docker"
    warn "执行后 openppp2 会因 restart: unless-stopped 自动拉起。"
  fi

  echo
  echo "===== 完成 ====="
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND/-/ } logs -f <服务名>"
  echo
  info "安全配置：使用自定义 seccomp 配置（仅放开必要的 io_uring 系统调用）。"
}

do_uninstall() {
  require_root
  info "开始卸载 openppp2（不卸载 Docker）..."

  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
    systemctl disable --now openppp2-boot.service  >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh \
        /etc/systemd/system/openppp2-boot.service \
        /usr/local/bin/openppp2-wait-uptime.sh \
        /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  if need_cmd docker; then
    local containers
    containers="$(docker ps -a --filter name=openppp2 --format '{{.Names}}' 2>/dev/null || true)"
    if [[ -n "$containers" ]]; then
      info "停止并删除 openppp2 容器..."
      for c in $containers; do
        docker rm -f "$c" >/dev/null 2>&1 || true
      done
    fi
  fi

  if [[ -d "$APP_DIR" ]] && need_cmd docker; then
    (cd "$APP_DIR" && {
       detect_compose >/dev/null 2>&1 || true
       if [[ -n "$COMPOSE_KIND" ]]; then
         info "停止并清理 compose 资源..."
         compose down --remove-orphans >/dev/null 2>&1 || true
       fi
    }) || true
  fi

  local KEEP_BACKUP
  prompt_yesno KEEP_BACKUP "是否保留备份文件（backups 目录）？" "yes"

  if [[ "$KEEP_BACKUP" == "yes" ]]; then
    local tmp_backup=""
    if [[ -d "$BACKUP_DIR" ]]; then
      tmp_backup="/tmp/openppp2-backups-$(date +%Y%m%d_%H%M%S)"
      mv "$BACKUP_DIR" "$tmp_backup" >/dev/null 2>&1 || true
    fi

    if need_cmd docker; then
      local running
      running="$(docker ps --filter name=openppp2 --format '{{.Names}}' 2>/dev/null || true)"
      if [[ -n "$running" ]]; then
        warn "以下容器仍在运行，请手动停止后再卸载：$running"
        die "卸载中止：仍有运行中的 openppp2 容器。"
      fi
    fi

    info "删除目录 ${APP_DIR} ..."
    rm -rf "$APP_DIR"

    if [[ -n "$tmp_backup" && -d "$tmp_backup" ]]; then
      mkdir -p "$APP_DIR"
      mv "$tmp_backup" "$BACKUP_DIR" >/dev/null 2>&1 || true
    fi
  else
    info "删除目录 ${APP_DIR} ..."
    rm -rf "$APP_DIR"
  fi

  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  remove_docker_proxy

  echo "卸载完成。"
}

# ============================================================
#  菜单入口
# ============================================================
main() {
  ensure_tty_stdin
  check_env_supported

  echo "=============================="
  echo "  openppp2 一键部署脚本  v${SCRIPT_VERSION}"
  echo "  仓库: ${REPO_URL}"
  echo "=============================="
  echo "请选择操作："
  echo "  1) 安装 openppp2"
  echo "  2) 卸载 openppp2"
  echo "  3) 新增 openppp2 客户端实例"
  echo "  4) 查看客户端配置和代理信息"
  echo "  5) 删除客户端实例/配置"
  echo "  6) 备份当前配置文件"
  echo "  7) 回滚（恢复最新备份）"
  echo "  0) 退出"
  echo "=============================="

  local ACTION
  prompt ACTION "请输入数字（0-7）" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_add_client ;;
    4) do_show_info ;;
    5) do_delete_client ;;
    6) do_backup ;;
    7) do_restore ;;
    0) echo "再见！"; exit 0 ;;
    *) die "输入错误，只能是 0 / 1 / 2 / 3 / 4 / 5 / 6 / 7。" ;;
  esac
}

main "$@"

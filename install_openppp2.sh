#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
SECCOMP_FILE="${APP_DIR}/seccomp-openppp2.json"

DEFAULT_IMAGE="ghcr.io/lucifer988/openppp2:latest"
DEFAULT_BASE_CFG_URL="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

DEFAULT_SECURITY_OPT_APPARMOR="apparmor=unconfined"

COMPOSE_KIND=""

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

has_systemd() {
  [[ -d /run/systemd/system ]] && need_cmd systemctl
}

die() {
  echo -e "[!]\t$*" >&2
  exit 1
}

info() {
  echo -e "[*]\t$*"
}

warn() {
  echo -e "[!]\t$*" >&2
}

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

prompt_port() {
  local __var="$1" __msg="$2" __def="${3:-20000}"
  local p=""
  while :; do
    prompt p "$__msg" "$__def"
    if [[ "$p" =~ ^[0-9]+$ ]] && [[ "$p" -ge 1 ]] && [[ "$p" -le 65535 ]]; then
      printf -v "$__var" "%s" "$p"
      return 0
    fi
    warn "端口必须是 1-65535 的纯数字（你输入的是：$p），请重新输入。"
  done
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

  # === FIX: avoid needrestart interactive prompt blocking scripts ===
  export NEEDRESTART_MODE=a
  export NEEDRESTART_SUSPEND=1
  # ================================================================

  local proxy_cfg="/etc/apt/apt.conf.d/99temp-proxy"

  if [[ -n "${http_proxy:-}" || -n "${HTTP_PROXY:-}" ]]; then
    local proxy="${http_proxy:-${HTTP_PROXY:-}}"
    info "检测到代理环境变量，为 APT 配置代理：${proxy}"
    cat > "$proxy_cfg" <<APTPROXYEOF
Acquire::http::Proxy "${proxy}";
Acquire::https::Proxy "${proxy}";
APTPROXYEOF
  fi

  info "正在更新软件包列表（最多等待 120 秒）..."
  if timeout 120 apt-get update -y 2>&1 | grep -v "^Get:" | grep -v "^Hit:" | grep -v "^Ign:" || true; then
    info "软件包列表更新完成"
  else
    warn "apt-get update 超时或失败，将继续尝试安装..."
  fi

  info "正在安装必要工具：$*"
  apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "$@"

  rm -f "$proxy_cfg" >/dev/null 2>&1 || true
}

curl_retry() {
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 --max-time 180 "$@"
}

force_apt_ipv4() {
  local cfg="/etc/apt/apt.conf.d/99force-ipv4"
  if [[ -f "$cfg" ]] && grep -q 'Acquire::ForceIPv4' "$cfg" 2>/dev/null; then
    info "APT 已设置为强制使用 IPv4。"
    return 0
  fi
  if ! need_cmd apt-get; then
    return 0
  fi
  info "正在为 APT 启用 IPv4 优先策略（避免 IPv6 卡住）..."
  cat > "$cfg" <<'APTEOF'
Acquire::ForceIPv4 "true";
APTEOF
  info "APT 已强制使用 IPv4：$cfg"
}

ensure_basic_tools() {
  force_apt_ipv4

  local missing_tools=()

  if ! need_cmd curl; then
    missing_tools+=("curl")
  fi
  if ! need_cmd jq; then
    missing_tools+=("jq")
  fi
  if ! need_cmd ip; then
    missing_tools+=("iproute2")
  fi
  if ! need_cmd ss; then
    missing_tools+=("iproute2")
  fi

  missing_tools=($(printf '%s\n' "${missing_tools[@]}" | sort -u))

  if [[ "${#missing_tools[@]}" -gt 0 ]]; then
    if need_cmd apt-get; then
      info "检测到缺少工具：${missing_tools[*]}"

      if [[ -z "${http_proxy:-}" && -z "${HTTP_PROXY:-}" ]]; then
        echo
        local USE_APT_PROXY
        prompt USE_APT_PROXY "是否需要为 APT 配置 HTTP 代理加速下载？（yes/no）" "no"

        if [[ "$USE_APT_PROXY" == "yes" ]]; then
          local APT_PROXY_URL
          prompt APT_PROXY_URL "请输入 APT 代理地址（例如 http://127.0.0.1:7890）" "http://127.0.0.1:7890"
          export http_proxy="$APT_PROXY_URL"
          export https_proxy="$APT_PROXY_URL"
          info "已设置代理：${APT_PROXY_URL}"
        fi
      fi

      apt_install ca-certificates curl jq iproute2 gnupg
    else
      die "缺少必要工具且无法自动安装（非 apt 环境）：${missing_tools[*]}"
    fi
  else
    info "所有必要工具已安装。"
  fi

  need_cmd curl || die "curl 未安装成功，请手动安装 curl 后重试。"
  need_cmd jq   || die "jq 未安装成功，请手动安装 jq 后重试。"
  need_cmd ip   || die "ip 命令未找到，请安装 iproute2 后重试。"
  need_cmd ss   || die "ss 命令未找到，请安装 iproute2 / iproute2-ss 后重试。"
}

start_docker_daemon_soft() {
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  else
    service docker start >/dev/null 2>&1 || true
  fi
}

# === FIX: correct daemon check (original had a syntax/logic bug) ===
docker_daemon_ok() {
  need_cmd docker || return 1
  docker info >/dev/null 2>&1
}
# =================================================================

print_docker_diagnose() {
  warn "Docker 诊断信息（用于排查 docker info 失败的真实原因）："
  warn "环境变量（可能污染 docker 连接目标）："
  echo "  DOCKER_HOST=${DOCKER_HOST-}" >&2
  echo "  DOCKER_CONTEXT=${DOCKER_CONTEXT-}" >&2
  if has_systemd; then
    warn "systemctl status docker："
    systemctl status docker --no-pager -l || true
    warn "journalctl -u docker（最近 120 行）："
    journalctl -u docker -n 120 --no-pager || true
  else
    warn "非 systemd 环境：请自行查看 docker daemon 日志。"
  fi
}

install_docker_from_debian() {
  info "尝试通过 Debian/Ubuntu 仓库安装 docker.io ..."
  apt_install docker.io
  start_docker_daemon_soft
  return 0
}

install_docker_compose_plugin_if_missing() {
  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    return 0
  fi

  if need_cmd apt-get; then
    info "正在安装 docker-compose-plugin..."
    apt_install docker-compose-plugin || true
  fi

  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    return 0
  fi

  if ! need_cmd docker-compose && need_cmd apt-get; then
    info "正在安装 docker-compose（兼容模式）..."
    apt_install docker-compose || true
  fi

  return 0
}

ensure_docker_stack() {
  ensure_basic_tools

  if docker_daemon_ok; then
    info "已检测到可用的 Docker 环境。"
  else
    # === FIX: Debian + Ubuntu both use apt; don't rely on /etc/debian_version ===
    if need_cmd apt-get; then
      warn "当前系统未检测到可用的 Docker，尝试通过 apt 安装 docker.io ..."
      install_docker_from_debian || warn "通过 apt 安装 docker.io 失败，请手动安装 Docker。"
    else
      warn "系统未检测到 docker，且无法自动安装（非 apt 环境）。"
    fi
    # ==========================================================================
  fi

  if ! docker_daemon_ok; then
    print_docker_diagnose
    die "Docker daemon 不可用（或 docker CLI 无法连接）。请先确保 docker info 正常后再运行脚本。"
  fi

  install_docker_compose_plugin_if_missing

  if ! detect_compose; then
    die "未检测到 docker compose 或 docker-compose。请先安装 compose 后再运行脚本。"
  fi

  info "已选择使用 compose：${COMPOSE_KIND}"
}

gen_guid() {
  local u
  u="$(cat /proc/sys/kernel/random/uuid | tr '[:lower:]' '[:upper:]')"
  echo "{${u}}"
}

is_port_in_use() {
  local port="$1"
  ss -tuln 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/.*://g' | grep -qx "$port"
}

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

detect_net() {
  local out lan dev gw

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

download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"
  info "下载基准配置 appsettings.base.json ..."
  curl_retry -sS "$url" -o appsettings.base.json || die "下载失败：$url"
}

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

generate_seccomp_profile() {
  local seccomp_file="$1"
  info "生成自定义 seccomp 配置文件：${seccomp_file}"

  cat > "$seccomp_file" <<'SECCOMPEOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": [
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
      ]
    },
    {
      "architecture": "SCMP_ARCH_AARCH64",
      "subArchitectures": [
        "SCMP_ARCH_ARM"
      ]
    }
  ],
  "syscalls": [
    {
      "names": [
        "accept","accept4","access","adjtimex","alarm","bind","brk","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_time64","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","io_uring_enter","io_uring_register","io_uring_setup","ipc","kill","lchown","lchown32","lgetxattr","link","linkat","listen","listxattr","llistxattr","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","membarrier","memfd_create","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","nanosleep","newfstatat","open","openat","openat2","pause","pipe","pipe2","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","rename","renameat","renameat2","restart_syscall","rmdir","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socket","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0,"value": 0,"op": "SCMP_CMP_EQ"}]
    },
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0,"value": 8,"op": "SCMP_CMP_EQ"}]
    },
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0,"value": 131072,"op": "SCMP_CMP_EQ"}]
    },
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0,"value": 131080,"op": "SCMP_CMP_EQ"}]
    },
    {
      "names": ["personality"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0,"value": 4294967295,"op": "SCMP_CMP_EQ"}]
    },
    {
      "names": ["arch_prctl"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["modify_ldt"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["clone"],
      "action": "SCMP_ACT_ALLOW",
      "args": [{"index": 0,"value": 2114060288,"op": "SCMP_CMP_MASKED_EQ"}]
    },
    {
      "names": ["clone3"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 38
    }
  ]
}
SECCOMPEOF

  info "seccomp 配置文件已生成（仅放开 io_uring 相关系统调用，保留其他安全限制）"
}

setup_docker_proxy() {
  local proxy_ip="$1"
  local proxy_port="$2"

  if ! has_systemd; then
    warn "非 systemd 环境，无法自动配置 Docker 代理。"
    return 1
  fi

  info "配置 Docker HTTP 代理：${proxy_ip}:${proxy_port}"

  mkdir -p /etc/systemd/system/docker.service.d

  cat > /etc/systemd/system/docker.service.d/http-proxy.conf <<PROXYEOF
[Service]
Environment="HTTP_PROXY=http://${proxy_ip}:${proxy_port}"
Environment="HTTPS_PROXY=http://${proxy_ip}:${proxy_port}"
PROXYEOF

  systemctl daemon-reload
  systemctl restart docker

  sleep 2

  if ! docker_daemon_ok; then
    warn "Docker 重启后无法连接，可能代理配置有误。"
    return 1
  fi

  info "Docker 代理配置成功"
  return 0
}

remove_docker_proxy() {
  if ! has_systemd; then
    return 0
  fi

  if [[ -f /etc/systemd/system/docker.service.d/http-proxy.conf ]]; then
    info "删除 Docker 代理配置..."
    rm -f /etc/systemd/system/docker.service.d/http-proxy.conf
    systemctl daemon-reload
    systemctl restart docker
    sleep 2
    info "Docker 代理配置已删除"
  fi
}

compose_header() {
  if [[ "$COMPOSE_KIND" == "docker-compose" ]]; then
    echo 'version: "3.8"'
  fi
}

compose_security_opt_block() {
  cat <<'SECOPTEOF'
    security_opt:
      - seccomp=./seccomp-openppp2.json
      - apparmor=unconfined
SECOPTEOF
}

write_compose_server() {
  local image="$1" cfg="$2"
  compose_header > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<SERVEREOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
$(compose_security_opt_block)
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
SERVEREOF
}

write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun_name="$6" tun_ip="$7" tun_gw="$8" use_mux="${9:-no}"
  compose_header > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<CLIENTEOF
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
$(compose_security_opt_block)
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
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
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

append_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" ipfile="$6" dnsfile="$7" tun_name="$8" tun_ip="$9" tun_gw="${10}" use_mux="${11:-no}"
  cat >> "$COMPOSE_FILE" <<APPENDEOF

  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
$(compose_security_opt_block)
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
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
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

setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "无 systemd，跳过定时更新。可用 crontab 定时执行 /usr/local/bin/openppp2-update.sh"
    return 0
  fi

  echo
  info "设置 systemd 每周自动更新（pull + up -d）"
  local oncal
  prompt oncal "请输入 OnCalendar（按周）表达式" "${DEFAULT_ONCAL}"

  cat >/usr/local/bin/openppp2-update.sh <<'UPDATEEOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

"${dc[@]}" pull
"${dc[@]}" up -d --remove-orphans
UPDATEEOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'SERVICEEOF'
[Unit]
Description=Update openppp2 container images
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
SERVICEEOF

  cat >/etc/systemd/system/openppp2-update.timer <<TIMEREOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${oncal}
Persistent=true
Unit=openppp2-update.service

[Install]
WantedBy=timers.target
TIMEREOF

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer
  info "已启用 openppp2-update.timer"
}

health_check_one() {
  local svc="$1"
  if ! docker ps --format '{{.Names}}' | grep -qx "$svc"; then
    warn "容器未运行：${svc}"
    echo "  查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs --tail=200 ${svc}" >&2
    exit 1
  fi

  if docker logs "$svc" 2>/dev/null | tail -n 200 | grep -q 'io_uring_queue_init: Operation not permitted'; then
    warn "检测到 io_uring 被拒绝（Operation not permitted）。"
    warn "请检查 seccomp 配置文件是否正确加载。"
    echo "  查看日志：docker logs --tail=200 ${svc}" >&2
    exit 1
  fi
}

do_install() {
  ensure_docker_stack

  echo "=============================="
  echo "  请选择安装/部署角色："
  echo "    1) 服务端（Server）"
  echo "    2) 客户端（Client）"
  echo "=============================="
  local ROLE
  prompt ROLE "请输入数字选择（1 或 2）" "1"

  local IMAGE BASE_URL
  prompt IMAGE "请输入镜像地址" "${DEFAULT_IMAGE}"
  prompt BASE_URL "请输入基准配置文件 URL（appsettings.base.json 的 raw 链接）" "${DEFAULT_BASE_CFG_URL}"

  download_base_cfg "$BASE_URL"
  cd "$APP_DIR"

  generate_seccomp_profile "$SECCOMP_FILE"

  docker rm -f watchtower >/dev/null 2>&1 || true

  if [[ "$ROLE" == "1" ]]; then
    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的服务端配置文件名称（例如 appsettings.json）" "appsettings.json"

    local SERVER_PUBLIC_IP autoip=""
    autoip="$(curl_retry -sS https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "$autoip" ]]; then
      prompt SERVER_PUBLIC_IP "请输入服务端对外 IP 地址" "$autoip"
    else
      prompt SERVER_PUBLIC_IP "请输入服务端对外 IP 地址" ""
    fi

    jq --arg ip "$SERVER_PUBLIC_IP" \
       '.ip.public=$ip | .ip.interface=$ip' \
       appsettings.base.json > "$APP_CFG_NAME"

    write_compose_server "$IMAGE" "$APP_CFG_NAME"
    echo "server" > "${APP_DIR}/.role"

  elif [[ "$ROLE" == "2" ]]; then
    [[ -c /dev/net/tun ]] || die "/dev/net/tun 不存在：宿主机不支持 TUN，client 无法运行。"

    local APP_CFG_NAME
    prompt APP_CFG_NAME "请输入要生成的客户端配置文件名称（例如 appsettings-RFCHK.json）" "appsettings.json"

    local MAIN_SERVICE_NAME
    prompt MAIN_SERVICE_NAME "请输入主客户端实例名称（容器/服务名）" "openppp2"

    local SERVER_IP SERVER_PORT guid lan nic gw netinfo
    prompt SERVER_IP "请输入服务端 IP（例如 1.2.3.4）" ""
    prompt_port SERVER_PORT "请输入服务端端口（例如 20000）" "20000"

    guid="$(gen_guid)"
    netinfo="$(detect_net)"
    lan="${netinfo%%|*}"
    netinfo="${netinfo#*|}"
    nic="${netinfo%%|*}"
    gw="${netinfo#*|}"

    if [[ -z "${lan:-}" || "${lan:-}" =~ ^10\. ]]; then
      warn "自动检测到的 LAN IP 为空或为 10.x（可能是隧道），请手动输入正确的内网 IP。"
      prompt lan "请输入客户端内网 IP（用于 http/socks bind，例如 192.168.1.100）" ""
    else
      info "检测到客户端内网 IP：${lan}"
    fi

    if [[ -z "${nic:-}" ]]; then
      warn "未能自动检测默认网卡名（dev），请手动输入。"
      prompt nic "请输入默认网卡名（例如 eth0、ens3、ens192）" ""
    else
      info "检测到默认网卡：${nic}"
    fi

    if [[ -z "${gw:-}" ]]; then
      warn "未能自动检测默认网关（via），请手动输入。"
      prompt gw "请输入默认网关（例如 192.168.1.1）" ""
    else
      info "检测到默认网关：${gw}"
    fi

    local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

    local HTTP_PORT SOCKS_PORT
    HTTP_PORT="$(random_free_port)"
    SOCKS_PORT="$(random_free_port)"
    while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do
      SOCKS_PORT="$(random_free_port)"
    done

    jq --arg srv "$SERVER_URI" \
       --arg guid "$guid" \
       --arg lan "$lan" \
       --argjson hport "$HTTP_PORT" \
       --argjson sport "$SOCKS_PORT" \
       '.client.server=$srv | .client.guid=$guid | .client["http-proxy"].bind=$lan | .client["socks-proxy"].bind=$lan | .client["http-proxy"].port=$hport | .client["socks-proxy"].port=$sport' \
       appsettings.base.json > "$APP_CFG_NAME"

    [[ -f ip.txt ]] || : > ip.txt
    [[ -f dns-rules.txt ]] || : > dns-rules.txt

    enable_ip_forward_host

    local tun_name="ppp0"
    local tun_ip="10.0.0.2"
    local tun_gw="10.0.0.1"

    local USE_MUX="no"
    prompt USE_MUX "是否开启 mux？(yes/no)" "no"
    write_compose_client "$IMAGE" "$nic" "$gw" "$MAIN_SERVICE_NAME" "$APP_CFG_NAME" "$tun_name" "$tun_ip" "$tun_gw" "$USE_MUX"

    echo "client" > "${APP_DIR}/.role"
    echo "$MAIN_SERVICE_NAME" > "${APP_DIR}/.client_main_service"

    echo
    echo "当前客户端配置信息："
    echo "  配置文件：${APP_CFG_NAME}"
    echo "  server   ：${SERVER_URI}"
    echo "  SOCKS5   ：${lan}:${SOCKS_PORT}"
    echo "  HTTP     ：${lan}:${HTTP_PORT}"
    echo "  tun-host ：no（已强制写入命令行参数）"

    echo
    local USE_PROXY
    prompt USE_PROXY "是否需要为 Docker 配置 HTTP 代理来拉取镜像？（yes/no）" "no"

    local proxy_configured=0
    if [[ "$USE_PROXY" == "yes" ]]; then
      local PROXY_IP PROXY_PORT
      prompt PROXY_IP "请输入代理服务器 IP 地址" ""
      prompt_port PROXY_PORT "请输入代理服务器端口" "7890"

      if setup_docker_proxy "$PROXY_IP" "$PROXY_PORT"; then
        proxy_configured=1
      else
        warn "代理配置失败，将不使用代理继续安装。"
      fi
    fi

  else
    die "角色选择错误，只能输入 1 或 2。"
  fi

  echo
  info "启动 openppp2..."
  cd "$APP_DIR"
  compose up -d --remove-orphans

  if [[ "$ROLE" == "2" ]]; then
    if [[ "$proxy_configured" -eq 1 ]]; then
      remove_docker_proxy
    fi

    health_check_one "$(cat "${APP_DIR}/.client_main_service" 2>/dev/null || echo openppp2)"
  else
    health_check_one "openppp2"
  fi

  setup_systemd_weekly_update

  echo
  echo "===== 完成 ====="
  echo "配置目录：${APP_DIR}"
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f <服务名>"
  echo
  info "安全配置：使用自定义 seccomp 配置（仅放开必要的 io_uring 系统调用）"
}

do_uninstall() {
  info "开始卸载 openppp2（不卸载 Docker）..."

  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/openppp2-update.timer \
        /etc/systemd/system/openppp2-update.service \
        /usr/local/bin/openppp2-update.sh >/dev/null 2>&1 || true
  if has_systemd; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  if need_cmd docker; then
    docker rm -f watchtower >/dev/null 2>&1 || true
  fi

  if [[ -d "$APP_DIR" ]] && need_cmd docker; then
    cd "$APP_DIR"
    detect_compose >/dev/null 2>&1 || true
    if [[ -n "$COMPOSE_KIND" ]]; then
      info "停止并删除容器..."
      compose down --remove-orphans >/dev/null 2>&1 || true
    else
      docker rm -f openppp2 >/dev/null 2>&1 || true
    fi
  fi

  info "删除目录 ${APP_DIR} ..."
  rm -rf "$APP_DIR"

  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  remove_docker_proxy

  echo "卸载完成。"
}

do_add_client() {
  ensure_docker_stack

  if [[ ! -d "$APP_DIR" ]] || [[ ! -f "$COMPOSE_FILE" ]]; then
    die "未检测到已有安装，请先用 1) 安装 openppp2（client）后再用 3) 新增。"
  fi

  local role="unknown"
  if [[ -f "${APP_DIR}/.role" ]]; then
    role="$(cat "${APP_DIR}/.role" 2>/dev/null || echo unknown)"
  fi
  if [[ "$role" != "client" ]]; then
    die "当前安装不是 client（可能是 server），按要求禁止使用 3) 新增。"
  fi

  cd "$APP_DIR"

  if [[ ! -f "$SECCOMP_FILE" ]]; then
    info "未找到 seccomp 配置文件，正在生成..."
    generate_seccomp_profile "$SECCOMP_FILE"
  fi

  if [[ ! -f appsettings.base.json ]]; then
    local BASE_URL
    prompt BASE_URL "未找到 appsettings.base.json，请输入 URL" "${DEFAULT_BASE_CFG_URL}"
    download_base_cfg "$BASE_URL"
  fi

  local IMAGE
  IMAGE="$(awk '/image:/ {print $2; exit}' "$COMPOSE_FILE" 2>/dev/null || true)"
  if [[ -z "$IMAGE" ]]; then
    prompt IMAGE "未能解析镜像地址，请输入镜像地址" "${DEFAULT_IMAGE}"
  fi

  local SERVER_IP SERVER_PORT guid lan nic gw netinfo
  prompt SERVER_IP "请输入新增客户端要连接的服务端 IP（例如 1.2.3.4）" ""
  prompt_port SERVER_PORT "请输入新增客户端要连接的服务端端口（例如 20000）" "20000"

  guid="$(gen_guid)"
  netinfo="$(detect_net)"
  lan="${netinfo%%|*}"
  netinfo="${netinfo#*|}"
  nic="${netinfo%%|*}"
  gw="${netinfo#*|}"

  if [[ -z "${lan:-}" || "${lan:-}" =~ ^10\. ]]; then
    warn "自动检测到的 LAN IP 为空或为 10.x（可能是隧道），请手动输入正确的内网 IP。"
    prompt lan "请输入客户端内网 IP（用于 http/socks bind，例如 192.168.1.100）" ""
  else
    info "检测到客户端内网 IP：${lan}"
  fi

  if [[ -z "${nic:-}" ]]; then
    warn "未能自动检测默认网卡名（dev），请手动输入。"
    prompt nic "请输入默认网卡名（例如 eth0、ens3、ens192）" ""
  else
    info "检测到默认网卡：${nic}"
  fi

  if [[ -z "${gw:-}" ]]; then
    warn "未能自动检测默认网关（via），请手动输入。"
    prompt gw "请输入默认网关（例如 192.168.1.1）" ""
  else
    info "检测到默认网关：${gw}"
  fi

  local SERVER_URI="ppp://${SERVER_IP}:${SERVER_PORT}/"

  local idx=2
  while grep -q "openppp2-${idx}:" "$COMPOSE_FILE" 2>/dev/null; do
    idx=$(( idx + 1 ))
  done
  local default_svc="openppp2-${idx}"

  local SVC_NAME
  prompt SVC_NAME "请输入新客户端实例名称（容器/服务名）" "$default_svc"

  # === small robustness: check under services indentation ===
  if grep -qE "^[[:space:]]{2}${SVC_NAME}:[[:space:]]*$" "$COMPOSE_FILE" 2>/dev/null; then
    die "服务名 ${SVC_NAME} 已存在，请换一个名称。"
  fi
  # =========================================================

  local cfg_default="appsettings-${SVC_NAME}.json"
  local CFG_NAME
  prompt CFG_NAME "请输入该客户端配置文件名称" "$cfg_default"

  local ipfile="ip-${SVC_NAME}.txt"
  local dnsfile="dns-rules-${SVC_NAME}.txt"

  local tun_idx="$idx"
  local tun_ip="10.0.${tun_idx}.2"
  local tun_gw="10.0.${tun_idx}.1"
  local tun_name="ppp${tun_idx}"

  local HTTP_PORT SOCKS_PORT
  HTTP_PORT="$(random_free_port)"
  SOCKS_PORT="$(random_free_port)"
  while [[ "$SOCKS_PORT" == "$HTTP_PORT" ]]; do
    SOCKS_PORT="$(random_free_port)"
  done

  jq --arg srv "$SERVER_URI" \
     --arg guid "$guid" \
     --arg lan "$lan" \
     --argjson hport "$HTTP_PORT" \
     --argjson sport "$SOCKS_PORT" \
     '.client.server=$srv | .client.guid=$guid | .client["http-proxy"].bind=$lan | .client["socks-proxy"].bind=$lan | .client["http-proxy"].port=$hport | .client["socks-proxy"].port=$sport' \
     appsettings.base.json > "${CFG_NAME}"

  [[ -f "$ipfile" ]] || : > "$ipfile"
  [[ -f "$dnsfile" ]] || : > "$dnsfile"

  enable_ip_forward_host

  local USE_MUX="no"
  prompt USE_MUX "是否开启 mux？(yes/no)" "no"
  append_compose_client "${IMAGE}" "${nic}" "${gw}" "${SVC_NAME}" "${CFG_NAME}" "${ipfile}" "${dnsfile}" "${tun_name}" "${tun_ip}" "${tun_gw}" "$USE_MUX"

  echo
  local USE_PROXY
  prompt USE_PROXY "是否需要为 Docker 配置 HTTP 代理来拉取镜像？（yes/no）" "no"

  local proxy_configured=0
  if [[ "$USE_PROXY" == "yes" ]]; then
    local PROXY_IP PROXY_PORT
    prompt PROXY_IP "请输入代理服务器 IP 地址" ""
    prompt_port PROXY_PORT "请输入代理服务器端口" "7890"

    if setup_docker_proxy "$PROXY_IP" "$PROXY_PORT"; then
      proxy_configured=1
    else
      warn "代理配置失败，将不使用代理继续安装。"
    fi
  fi

  info "启动新增客户端实例：${SVC_NAME} ..."
  compose up -d --remove-orphans "${SVC_NAME}"

  if [[ "$proxy_configured" -eq 1 ]]; then
    remove_docker_proxy
  fi

  health_check_one "${SVC_NAME}"

  echo
  echo "当前新增客户端配置信息："
  echo "  配置文件：${CFG_NAME}"
  echo "  server   ：${SERVER_URI}"
  echo "  SOCKS5   ：${lan}:${SOCKS_PORT}"
  echo "  HTTP     ：${lan}:${HTTP_PORT}"
  echo "  tun-host ：no（已强制写入命令行参数）"
  echo
  echo "查看日志：cd ${APP_DIR} && ${COMPOSE_KIND} logs -f ${SVC_NAME}"
}

do_show_info() {
  [[ -d "$APP_DIR" ]] || die "未检测到 ${APP_DIR} 目录，似乎尚未安装 openppp2。"
  cd "$APP_DIR"

  local found=0
  for f in appsettings*.json; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "appsettings.base.json" ]] && continue

    local server socks_bind socks_port http_bind http_port
    server="$(jq -r '(.client.server // empty)' "$f")"
    [[ -z "$server" ]] && continue

    socks_bind="$(jq -r '(.client["socks-proxy"].bind // "")' "$f")"
    socks_port="$(jq -r '(.client["socks-proxy"].port // "")' "$f")"
    http_bind="$(jq -r '(.client["http-proxy"].bind // "")' "$f")"
    http_port="$(jq -r '(.client["http-proxy"].port // "")' "$f")"

    found=1
    echo "----------------------------------------"
    echo "配置文件：$f"
    echo "  client.server ：$server"
    echo "  SOCKS5        ：${socks_bind}:${socks_port}"
    echo "  HTTP          ：${http_bind}:${http_port}"
  done

  if [[ "$found" -eq 0 ]]; then
    echo "未找到包含 client.server 的客户端配置文件。"
  else
    echo "----------------------------------------"
    echo "以上为当前所有客户端配置的 server / SOCKS5 / HTTP 信息"
  fi
}

CLIENT_CFG_LIST=()

list_client_cfgs() {
  cd "$APP_DIR"
  CLIENT_CFG_LIST=()
  local f
  for f in appsettings*.json; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "appsettings.base.json" ]] && continue
    if jq -e '.client.server? // empty' "$f" >/dev/null 2>&1; then
      CLIENT_CFG_LIST+=("$f")
    fi
  done
  [[ "${#CLIENT_CFG_LIST[@]}" -gt 0 ]]
}

print_client_cfgs() {
  local i=1
  local f
  for f in "${CLIENT_CFG_LIST[@]}"; do
    echo "  $i) $f" >&2
    i=$(( i + 1 ))
  done
}

find_service_by_cfg() {
  local cfg="$1"
  awk -v cfg="$cfg" '
    BEGIN{svc=""}
    /^[[:space:]]{2}[A-Za-z0-9_.-]+:[[:space:]]*$/ {svc=$1; sub(":", "", svc)}
    index($0, "./" cfg) > 0 { if (svc!="") { print svc; exit } }
  ' "$COMPOSE_FILE"
}

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

select_cfg_interactive() {
  echo >&2
  echo "可删除的客户端配置文件列表：" >&2
  print_client_cfgs
  echo >&2
  echo "你可以：" >&2
  echo "  - 输入编号（例如 2）" >&2
  echo "  - 或输入配置文件名/关键词（例如 RFCHK 或 appsettings-RFCHK.json）" >&2
  echo >&2

  local sel=""
  read -r -p "请输入要删除的配置（编号/名称/关键词）: " sel

  if [[ "$sel" =~ ^[0-9]+$ ]]; then
    local idx="$sel"
    local max_idx="${#CLIENT_CFG_LIST[@]}"
    if [[ "$idx" -ge 1 ]] && [[ "$idx" -le "$max_idx" ]]; then
      local arr_idx=$(( idx - 1 ))
      echo "${CLIENT_CFG_LIST[$arr_idx]}"
      return 0
    fi
    die "编号无效。"
  fi

  if [[ -f "${APP_DIR}/${sel}" ]]; then
    echo "$sel"
    return 0
  fi

  local matches=()
  local f
  for f in "${CLIENT_CFG_LIST[@]}"; do
    if [[ "$f" == *"$sel"* ]]; then
      matches+=("$f")
    fi
  done

  if [[ "${#matches[@]}" -eq 1 ]]; then
    echo "${matches[0]}"
    return 0
  fi

  if [[ "${#matches[@]}" -gt 1 ]]; then
    echo >&2
    warn "匹配到多个配置，请输入更精确的名称："
    local i=1
    for f in "${matches[@]}"; do
      echo "  $i) $f" >&2
      i=$(( i + 1 ))
    done
    die "请重新运行选项 5 并输入更精确的关键词/文件名。"
  fi

  die "未找到匹配的配置文件：$sel"
}

do_delete_client() {
  ensure_docker_stack

  [[ -d "$APP_DIR" ]] || die "未检测到 ${APP_DIR}，请先安装。"
  [[ -f "$COMPOSE_FILE" ]] || die "未找到 ${COMPOSE_FILE}，请先安装。"

  local role="unknown"
  if [[ -f "${APP_DIR}/.role" ]]; then
    role="$(cat "${APP_DIR}/.role" 2>/dev/null || echo unknown)"
  fi
  if [[ "$role" != "client" ]]; then
    die "当前环境不是 client（或未按脚本安装），为安全起见不提供删除。"
  fi

  cd "$APP_DIR"

  if ! list_client_cfgs; then
    echo "未找到可删除的客户端配置文件。"
    return 0
  fi

  local cfg
  cfg="$(select_cfg_interactive)"

  local svc=""
  svc="$(find_service_by_cfg "$cfg" || true)"

  echo
  echo "即将删除："
  echo "  配置文件：$cfg"
  echo "  对应服务：${svc:-（未能自动定位）}"
  echo

  local yesno
  prompt yesno "确认删除？输入 yes 继续" "no"
  if [[ "$yesno" != "yes" ]]; then
    echo "已取消。"
    return 0
  fi

  if [[ -n "$svc" ]]; then
    info "停止并移除 service/container：$svc"
    compose stop "$svc" >/dev/null 2>&1 || true
    compose rm -f "$svc" >/dev/null 2>&1 || true

    info "从 docker-compose.yml 移除 service：$svc"
    remove_service_block "$svc"

    rm -f "ip-${svc}.txt" "dns-rules-${svc}.txt" >/dev/null 2>&1 || true
  else
    warn "未能定位 service：将仅删除配置文件本身（若实例仍会被拉起，请手动从 docker-compose.yml 移除对应 service）。"
  fi

  info "删除配置文件：$cfg"
  rm -f "$cfg" >/dev/null 2>&1 || true

  info "清理孤儿并刷新运行状态..."
  compose up -d --remove-orphans >/dev/null 2>&1 || true

  echo
  echo "删除完成。建议用 4) 查看客户端配置和代理信息 确认结果。"
}

check_env_supported() {
  is_root || die "请使用 root 身份执行本脚本，例如：sudo bash $0"
  [[ -f /etc/debian_version ]] || warn "未检测到 /etc/debian_version，系统可能不是标准 Debian/Ubuntu。"
}

main() {
  check_env_supported

  echo "=============================="
  echo "  openppp2 一键部署脚本"
  echo "=============================="
  echo "请选择操作："
  echo "  1) 安装 openppp2"
  echo "  2) 卸载 openppp2"
  echo "  3) 新增 openppp2 客户端实例"
  echo "  4) 查看客户端配置和代理信息"
  echo "  5) 删除客户端实例/配置（避免重启反复拉起）"
  echo "=============================="

  local ACTION
  prompt ACTION "请输入数字选择（1 / 2 / 3 / 4 / 5）" "1"

  case "$ACTION" in
    1) do_install ;;
    2) do_uninstall ;;
    3) do_add_client ;;
    4) do_show_info ;;
    5) do_delete_client ;;
    *) die "输入错误，只能是 1 / 2 / 3 / 4 / 5。" ;;
  esac
}

############################################
# PATCH SECTION (追加覆盖版)
# - 1) Client 优先 ens192（支持 CLIENT_NIC=xxx 强制）
# - 2) 重启后延迟 20 秒再拉起容器（systemd 控制）
# - 3) 保留你原有的日志轮转覆盖
# 说明：只通过“后定义函数覆盖前定义”的 Bash 机制生效
############################################

# 默认客户端网卡（存在才用；不存在回退原探测）
DEFAULT_CLIENT_NIC="${DEFAULT_CLIENT_NIC:-ens192}"
# 开机延迟（秒），默认 20；可用 OPENPPP2_BOOT_DELAY 覆盖；设 0 禁用
DEFAULT_BOOT_DELAY="${DEFAULT_BOOT_DELAY:-20}"

setup_systemd_boot_delay_start() {
  if ! has_systemd; then
    warn "无 systemd，跳过开机延迟启动。"
    return 0
  fi

  local delay="${OPENPPP2_BOOT_DELAY:-$DEFAULT_BOOT_DELAY}"
  if ! [[ "$delay" =~ ^[0-9]+$ ]]; then
    warn "OPENPPP2_BOOT_DELAY 非纯数字：${delay}，回退为 ${DEFAULT_BOOT_DELAY}"
    delay="$DEFAULT_BOOT_DELAY"
  fi

  if [[ "$delay" -le 0 ]]; then
    info "OPENPPP2_BOOT_DELAY=${delay}：已禁用开机延迟启动（openppp2-boot.service）"
    systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/openppp2-boot.service \
          /usr/local/bin/openppp2-wait-uptime.sh \
          /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    return 0
  fi

  cat >/usr/local/bin/openppp2-wait-uptime.sh <<'WAITEOF'
#!/usr/bin/env bash
set -euo pipefail
delay="${1:-20}"
if ! [[ "$delay" =~ ^[0-9]+$ ]]; then delay=20; fi
up="$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
if [[ "$up" -lt "$delay" ]]; then
  sleep $(( delay - up ))
fi
WAITEOF
  chmod +x /usr/local/bin/openppp2-wait-uptime.sh

  cat >/usr/local/bin/openppp2-stack.sh <<'STACKEOF'
#!/usr/bin/env bash
set -euo pipefail

cd /opt/openppp2 2>/dev/null || exit 0
[[ -f docker-compose.yml ]] || exit 0

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

case "${1:-start}" in
  start)
    "${dc[@]}" up -d --remove-orphans
    ;;
  stop)
    # down：防止 docker restart policy 抢跑（下次开机由本 service 延迟启动）
    "${dc[@]}" down --remove-orphans || true
    ;;
  restart)
    "${dc[@]}" down --remove-orphans || true
    "${dc[@]}" up -d --remove-orphans
    ;;
  *)
    echo "usage: $0 {start|stop|restart}" >&2
    exit 2
    ;;
esac
STACKEOF
  chmod +x /usr/local/bin/openppp2-stack.sh

  cat >/etc/systemd/system/openppp2-boot.service <<SERVICEEOF
[Unit]
Description=Delayed start openppp2 stack (wait uptime >= ${delay}s)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/local/bin/openppp2-wait-uptime.sh ${delay}
ExecStart=/usr/local/bin/openppp2-stack.sh start
ExecStop=/usr/local/bin/openppp2-stack.sh stop
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
SERVICEEOF

  systemctl daemon-reload
  systemctl enable --now openppp2-boot.service
  info "已启用 openppp2-boot.service：开机后等待 uptime≥${delay}s 再启动 openppp2（关机时 down 防抢跑）"
}

# 覆盖：每周更新，末尾追加开机延迟启动启用
setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "无 systemd，跳过定时更新。可用 crontab 定时执行 /usr/local/bin/openppp2-update.sh"
    return 0
  fi

  echo
  info "设置 systemd 每周自动更新（pull + up -d）"
  local oncal
  prompt oncal "请输入 OnCalendar（按周）表达式" "${DEFAULT_ONCAL}"

  cat >/usr/local/bin/openppp2-update.sh <<'UPDATEEOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

"${dc[@]}" pull
"${dc[@]}" up -d --remove-orphans
UPDATEEOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'SERVICEEOF'
[Unit]
Description=Update openppp2 container images
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
SERVICEEOF

  cat >/etc/systemd/system/openppp2-update.timer <<TIMEREOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${oncal}
Persistent=true
Unit=openppp2-update.service

[Install]
WantedBy=timers.target
TIMEREOF

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer
  info "已启用 openppp2-update.timer"

  # NEW: 开机延迟启动（默认 20 秒）
  setup_systemd_boot_delay_start
}

# 覆盖：卸载时额外清理 openppp2-boot.service
do_uninstall() {
  info "开始卸载 openppp2（不卸载 Docker）..."

  if has_systemd; then
    systemctl disable --now openppp2-update.timer >/dev/null 2>&1 || true
    systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
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
    docker rm -f watchtower >/dev/null 2>&1 || true
  fi

  if [[ -d "$APP_DIR" ]] && need_cmd docker; then
    cd "$APP_DIR"
    detect_compose >/dev/null 2>&1 || true
    if [[ -n "$COMPOSE_KIND" ]]; then
      info "停止并删除容器..."
      compose down --remove-orphans >/dev/null 2>&1 || true
    else
      docker rm -f openppp2 >/dev/null 2>&1 || true
    fi
  fi

  info "删除目录 ${APP_DIR} ..."
  rm -rf "$APP_DIR"

  rm -f /etc/sysctl.d/99-openppp2.conf >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true

  remove_docker_proxy

  echo "卸载完成。"
}

# 覆盖：客户端网卡选择优先 ens192（或 CLIENT_NIC 指定）
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

  # ===== 原始探测逻辑保持不变 =====
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

############################################
# Docker 日志自动轮转（追加覆盖版）——保留你的写法
############################################
compose_logging_block() {
  cat <<'LOGEOF'
    logging:
      driver: "json-file"
      options:
        max-size: "20m"
        max-file: "5"
LOGEOF
}

write_compose_server() {
  local image="$1" cfg="$2"
  compose_header > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<SERVEREOF
services:
  openppp2:
    image: ${image}
    container_name: openppp2
    restart: unless-stopped
$(compose_security_opt_block)
$(compose_logging_block)
    volumes:
      - ./${cfg}:/opt/openppp2/appsettings.json:ro
    ports:
      - "20000:20000/tcp"
      - "20000:20000/udp"
SERVEREOF
}

write_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" tun_name="$6" tun_ip="$7" tun_gw="$8" use_mux="${9:-no}"
  compose_header > "$COMPOSE_FILE"
  cat >> "$COMPOSE_FILE" <<CLIENTEOF
services:
  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
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
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
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

append_compose_client() {
  local image="$1" nic="$2" gw="$3" svc="$4" cfg="$5" ipfile="$6" dnsfile="$7" tun_name="$8" tun_ip="$9" tun_gw="${10}" use_mux="${11:-no}"
  cat >> "$COMPOSE_FILE" <<APPENDEOF

  ${svc}:
    image: ${image}
    container_name: ${svc}
    restart: unless-stopped
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
      - "--bypass-iplist=ip.txt"
      - "--dns-rules=dns-rules.txt"
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

# 关键：main 放到文件最后，保证以上“覆盖版”全部生效
main "$@"

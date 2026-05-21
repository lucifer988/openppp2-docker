#!/usr/bin/env bash
# lib/core.sh — 公共工具函数：日志、交互、依赖、网络下载
#
# v2.3 防卡死改动：
#   1) prompt() 在 NONINTERACTIVE=1 时不再 read（直接用默认值或环境变量），
#      避免脚本通过 curl|bash / ssh 管道运行时永远阻塞
#   2) read 加 5 分钟 timeout，5 分钟没人按回车就用默认值往下走
#   3) apt_install 用 timeout 命令兜底，到点强制结束
#   4) curl_retry 显式 --max-time / --connect-timeout / --no-keepalive，
#      绝对不会无限等
#   5) safer_cd/safer_back 用 pushd/popd 避免函数嵌套时 cwd 错乱

# 读取共用常量
SCRIPT_DIR_CORE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR_CORE}/config.sh" ]] && source "${SCRIPT_DIR_CORE}/config.sh"

# === 基础探测 ===
need_cmd() { command -v "$1" >/dev/null 2>&1; }
is_root()  { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
has_systemd() { [[ -d /run/systemd/system ]] && need_cmd systemctl; }

# === 日志 ===
die()  { echo -e "[!]\t$*" >&2; exit 1; }
info() { echo -e "[*]\t$*"; }
warn() { echo -e "[!]\t$*" >&2; }
step() { echo -e "\n\033[1;36m==> $*\033[0m"; }

# === 安全目录切换：用 pushd/popd ===
safer_cd()   { pushd "$1" >/dev/null || die "无法切换到目录：$1"; }
safer_back() { popd  >/dev/null || die "popd 失败：目录栈异常"; }

# === 后台 spinner ：长操作时给用户看的"我没死"信号 ===
# 用法：
#   start_spinner "正在拉取镜像"
#   docker pull ...
#   stop_spinner
SPINNER_PID=""
start_spinner() {
  local msg="${1:-working...}"
  [[ "$NONINTERACTIVE" == "1" ]] && { info "$msg"; return 0; }
  (
    local i=0 chars='-\|/'
    while :; do
      i=$(( (i+1) % 4 ))
      printf "\r[%s] %s " "${chars:$i:1}" "$msg" >&2
      sleep 0.3
    done
  ) &
  SPINNER_PID=$!
  disown 2>/dev/null || true
}
stop_spinner() {
  if [[ -n "$SPINNER_PID" ]]; then
    kill "$SPINNER_PID" >/dev/null 2>&1 || true
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
    printf "\r\033[K" >&2  # 清除当前行
  fi
}
# 进程异常退出时，把 spinner 也清理掉
trap 'stop_spinner' EXIT INT TERM

# ============================================================
# prompt — 交互输入（v2.3 防卡死版）
# ============================================================
# 行为：
#   1. 优先使用同名环境变量（覆盖一切交互）
#   2. NONINTERACTIVE=1 → 直接用默认值，不 read
#   3. 否则 read 加 300s 超时；超时 → 警告并退到默认值
# ============================================================
prompt() {
  local __var="$1" __msg="$2" __def="${3:-}"
  local __val=""

  # 1) 同名环境变量优先
  local __env_val="${!__var-}"
  if [[ -n "$__env_val" ]]; then
    printf -v "$__var" "%s" "$__env_val"
    info "使用环境变量 ${__var}=${__env_val}"
    return 0
  fi

  # 2) 非交互模式，直接用默认值
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    if [[ -n "$__def" ]]; then
      printf -v "$__var" "%s" "$__def"
      info "[非交互] ${__var}=${__def}"
      return 0
    else
      die "[非交互] 必填项 ${__var} 没有默认值，无法继续。请用环境变量传入：export ${__var}=<value>"
    fi
  fi

  # 3) 交互模式，5 分钟超时
  if [[ -n "$__def" ]]; then
    if ! read -r -t 300 -p "$__msg [$__def]: " __val; then
      echo
      warn "5 分钟没有输入，使用默认值 [$__def] 继续"
      __val="$__def"
    fi
    __val="${__val:-$__def}"
  else
    if ! read -r -t 300 -p "$__msg: " __val; then
      echo
      die "5 分钟没有输入且无默认值，安装中止"
    fi
  fi
  printf -v "$__var" "%s" "$__val"
}

# === prompt_port — 端口号校验 ===
prompt_port() {
  local __var="$1" __msg="$2" __def="${3:-20000}"
  local p="" tries=0
  while :; do
    prompt p "$__msg" "$__def"
    if [[ "$p" =~ ^[0-9]+$ ]] && [[ "$p" -ge 1 ]] && [[ "$p" -le 65535 ]]; then
      printf -v "$__var" "%s" "$p"
      return 0
    fi
    warn "端口必须是 1-65535 的纯数字（你输入的是：$p），请重新输入。"
    tries=$((tries+1))
    if [[ $tries -ge 3 ]]; then
      die "端口输入连续 3 次错误，安装中止。"
    fi
  done
}

# ============================================================
# curl_retry — 带强制超时的下载
# ============================================================
# 关键防卡死参数：
#   --connect-timeout       TCP 握手超时（NET_CONNECT_TIMEOUT 秒）
#   --max-time              整个请求超时（NET_TIMEOUT 秒）
#   --retry 3 / --retry-delay 2 重试 3 次每次间隔 2 秒
#   --retry-all-errors      连 HTTP 5xx / 部分 4xx 也重试（curl 7.71+）
#   --no-keepalive          避免 keep-alive 在中间网络黑洞里卡死
#   -fL                     4xx/5xx 报错；跟随重定向
# ============================================================
curl_retry() {
  curl -fL \
       --connect-timeout "${NET_CONNECT_TIMEOUT}" \
       --max-time "${NET_TIMEOUT}" \
       --retry 3 \
       --retry-delay 2 \
       --retry-all-errors \
       --no-keepalive \
       "$@"
}

# === maybe_prompt_apt_proxy_for_client ===
maybe_prompt_apt_proxy_for_client() {
  local install_role="${1:-unknown}"

  [[ "$install_role" != "client" ]] && return 0
  [[ "${APT_PROXY_PROMPTED:-0}" -eq 1 ]] && return 0
  APT_PROXY_PROMPTED=1

  if [[ -n "${http_proxy:-}" || -n "${HTTP_PROXY:-}" ]]; then
    info "检测到现有代理环境变量，客户端 APT 将直接复用该代理。"
    return 0
  fi

  echo
  local USE_APT_PROXY
  prompt USE_APT_PROXY "客户端安装依赖时是否需要为 APT 配置 HTTP 代理？（yes/no）" "no"

  if [[ "$USE_APT_PROXY" == "yes" ]]; then
    local APT_PROXY_URL
    prompt APT_PROXY_URL "请输入 APT 代理地址（例如 http://127.0.0.1:7890）" "http://127.0.0.1:7890"
    export http_proxy="$APT_PROXY_URL"
    export https_proxy="$APT_PROXY_URL"
    export HTTP_PROXY="$APT_PROXY_URL"
    export HTTPS_PROXY="$APT_PROXY_URL"
    info "已设置 APT 代理：${APT_PROXY_URL}"
  else
    info "客户端未启用 APT 代理，继续直连安装依赖。"
  fi
}

# ============================================================
# apt_install — 防卡死版
# ============================================================
# 改动：
#   1) 显式 noninteractive 环境变量（防 dpkg 弹配置文件冲突对话框）
#   2) 用 `timeout` 命令给 apt-get update 和 install 都加硬超时
#   3) 失败时把日志 tail 出来给用户看，不再无声卡住
#   4) 自动等待 dpkg lock 释放（最长 60s），避免 unattended-upgrades 抢锁
# ============================================================
apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  export NEEDRESTART_SUSPEND=1
  export APT_LISTCHANGES_FRONTEND=none

  local proxy_cfg="/etc/apt/apt.conf.d/99temp-proxy"
  local apt_log="/tmp/openppp2-apt.log"

  # 代理透传到 apt
  if [[ -n "${http_proxy:-}" || -n "${HTTP_PROXY:-}" ]]; then
    local proxy="${http_proxy:-${HTTP_PROXY:-}}"
    info "检测到代理环境变量，为 APT 配置代理：${proxy}"
    cat > "$proxy_cfg" <<APTPROXYEOF
Acquire::http::Proxy "${proxy}";
Acquire::https::Proxy "${proxy}";
APTPROXYEOF
  fi

  # 等待 dpkg lock 释放（最长 60s）
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
        fuser /var/lib/apt/lists/lock        >/dev/null 2>&1; do
    if [[ $waited -ge 60 ]]; then
      warn "dpkg lock 持续被占用超过 60s（可能 unattended-upgrades 在跑），尝试继续..."
      break
    fi
    [[ $waited -eq 0 ]] && info "等待其他 apt 进程释放锁..."
    sleep 2
    waited=$((waited+2))
  done

  rm -f "$apt_log"

  info "正在更新软件包列表（最多 ${APT_TIMEOUT}s）..."
  if timeout "${APT_TIMEOUT}" apt-get update -y -o Acquire::Retries=2 >"$apt_log" 2>&1; then
    info "软件包列表更新完成"
  else
    warn "apt-get update 超时或失败，最后 30 行日志："
    tail -n 30 "$apt_log" >&2 || true
    warn "继续尝试安装..."
  fi

  info "安装必要工具：$*"
  if ! timeout "${APT_TIMEOUT}" apt-get install -y \
       --no-install-recommends \
       -o Dpkg::Options::=--force-confold \
       -o Dpkg::Options::=--force-confdef \
       "$@" >>"$apt_log" 2>&1; then
    warn "apt-get install 失败，最后 50 行日志："
    tail -n 50 "$apt_log" >&2 || true
    rm -f "$proxy_cfg"
    die "依赖安装失败，请检查上面的日志后重试。"
  fi

  rm -f "$proxy_cfg" "$apt_log"
}

# === force_apt_ipv4 — 防 IPv6 卡住 ===
force_apt_ipv4() {
  local cfg="/etc/apt/apt.conf.d/99force-ipv4"
  if [[ -f "$cfg" ]] && grep -q 'Acquire::ForceIPv4' "$cfg" 2>/dev/null; then
    return 0
  fi
  if ! need_cmd apt-get; then
    return 0
  fi
  info "为 APT 启用 IPv4 优先策略（避免 IPv6 卡住）..."
  echo 'Acquire::ForceIPv4 "true";' > "$cfg"
}

# === ensure_basic_tools — 装基础依赖 ===
ensure_basic_tools() {
  local install_role="${1:-unknown}"
  force_apt_ipv4

  local missing_tools=()
  need_cmd curl   || missing_tools+=("curl")
  need_cmd jq     || missing_tools+=("jq")
  need_cmd ip     || missing_tools+=("iproute2")
  need_cmd ss     || missing_tools+=("iproute2")
  need_cmd unzip  || missing_tools+=("unzip")
  need_cmd fuser  || missing_tools+=("psmisc")
  need_cmd timeout || missing_tools+=("coreutils")

  if [[ "${#missing_tools[@]}" -gt 0 ]]; then
    mapfile -t missing_tools < <(printf '%s\n' "${missing_tools[@]}" | sort -u)

    if need_cmd apt-get; then
      info "缺少工具：${missing_tools[*]}"
      maybe_prompt_apt_proxy_for_client "$install_role"
      apt_install ca-certificates curl jq iproute2 gnupg unzip psmisc coreutils
    else
      die "缺少必要工具且非 apt 环境：${missing_tools[*]}，请手动安装后重试。"
    fi
  else
    info "基础工具已就绪。"
  fi

  need_cmd curl    || die "curl 安装失败，请手动安装。"
  need_cmd jq      || die "jq 安装失败，请手动安装。"
  need_cmd ip      || die "iproute2 (ip) 安装失败。"
  need_cmd ss      || die "iproute2 (ss) 安装失败。"
}

# === gen_guid ===
gen_guid() {
  local u
  u="$(tr '[:lower:]' '[:upper:]' < /proc/sys/kernel/random/uuid)"
  echo "{${u}}"
}

# === download_base_cfg — 下载基准配置 ===
download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"

  # 如果同目录下有 appsettings.base.json 直接复制（离线友好）
  if [[ -f "${SCRIPT_DIR_CORE}/appsettings.base.json" ]]; then
    info "使用脚本目录内置的 appsettings.base.json（不联网下载）"
    cp "${SCRIPT_DIR_CORE}/appsettings.base.json" "${APP_DIR}/appsettings.base.json"
    return 0
  fi

  safer_cd "$APP_DIR"
  info "下载基准配置 appsettings.base.json（最多 ${NET_TIMEOUT}s）..."
  if ! curl_retry -sS "$url" -o appsettings.base.json; then
    safer_back
    die "下载失败：$url （超时或网络不通）"
  fi
  if [[ ! -s appsettings.base.json ]]; then
    safer_back
    die "下载到的 appsettings.base.json 是空文件，URL 可能错误。"
  fi
  safer_back
}

# === check_env_supported ===
check_env_supported() {
  is_root || die "请使用 root 身份执行本脚本，例如：sudo bash $0"
  [[ -f /etc/debian_version ]] || warn "未检测到 /etc/debian_version，系统可能不是标准 Debian/Ubuntu。"

  # 内核版本检查（io_uring 需要 5.1+）
  local kver kmajor kminor
  kver="$(uname -r | cut -d- -f1)"
  kmajor="${kver%%.*}"
  kminor="${kver#*.}"; kminor="${kminor%%.*}"
  if [[ "$kmajor" -lt 5 ]] || { [[ "$kmajor" -eq 5 ]] && [[ "$kminor" -lt 1 ]]; }; then
    warn "当前内核 ${kver} 较旧，io_uring 需要 5.1+，openppp2 可能无法启动。"
  fi
}

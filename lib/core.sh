#!/usr/bin/env bash
# lib/core.sh — 公共工具函数：日志、交互、依赖、网络下载
#
# 点 14 改动：
#   - curl_retry 已有完整选项，仅补充注释解释每个参数
#   - 新增 safer_cd / safer_back，用 pushd/popd 替代裸 cd，避免函数嵌套时弄丢 cwd

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === need_cmd ===
need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# === is_root ===
is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

# === has_systemd ===
has_systemd() {
  [[ -d /run/systemd/system ]] && need_cmd systemctl
}

# === die ===
die() {
  echo -e "[!]\t$*" >&2
  exit 1
}

# === info ===
info() {
  echo -e "[*]\t$*"
}

# === warn ===
warn() {
  echo -e "[!]\t$*" >&2
}

# === safer_cd / safer_back ===
# 安全的目录切换：用 pushd/popd 维护栈，避免「cd 进去之后忘了出来污染后续函数」。
# 失败立即 die，输出走 /dev/null 不污染 stdout（脚本里大量用 $(...) 捕获输出，
# 任何意外打印的 ~/foo 路径都会破坏 jq 解析）。
safer_cd() {
  local target="$1"
  pushd "$target" >/dev/null || die "无法切换到目录：$target"
}

safer_back() {
  popd >/dev/null || die "popd 失败：目录栈异常"
}

# === prompt ===
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

# === prompt_port ===
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

# === maybe_prompt_apt_proxy_for_client ===
maybe_prompt_apt_proxy_for_client() {
  local install_role="${1:-unknown}"

  if [[ "$install_role" != "client" ]]; then
    return 0
  fi

  if [[ "${APT_PROXY_PROMPTED:-0}" -eq 1 ]]; then
    return 0
  fi
  APT_PROXY_PROMPTED=1

  if [[ -n "${http_proxy:-}" || -n "${HTTP_PROXY:-}" ]]; then
    info "检测到现有代理环境变量，客户端 APT 将直接复用该代理。"
    return 0
  fi

  echo
  local USE_APT_PROXY
  prompt USE_APT_PROXY "客户端安装依赖时，是否需要为 APT 配置 HTTP 代理加速下载？（yes/no）" "no"

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

# === apt_install ===
apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  export NEEDRESTART_SUSPEND=1

  local proxy_cfg="/etc/apt/apt.conf.d/99temp-proxy"
  local apt_log="/tmp/openppp2-apt-update.log"

  if [[ -n "${http_proxy:-}" || -n "${HTTP_PROXY:-}" ]]; then
    local proxy="${http_proxy:-${HTTP_PROXY:-}}"
    info "检测到代理环境变量，为 APT 配置代理：${proxy}"
    cat > "$proxy_cfg" <<APTPROXYEOF
Acquire::http::Proxy "${proxy}";
Acquire::https::Proxy "${proxy}";
APTPROXYEOF
  fi

  info "正在更新软件包列表（最多等待 120 秒）..."
  rm -f "$apt_log" >/dev/null 2>&1 || true

  if timeout 120 apt-get update >"$apt_log" 2>&1; then
    info "软件包列表更新完成"
  else
    warn "apt-get update 超时或失败，将继续尝试安装..."
    tail -n 80 "$apt_log" >&2 || true
  fi

  info "正在安装必要工具：$*"
  apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "$@"

  rm -f "$proxy_cfg" "$apt_log" >/dev/null 2>&1 || true
}

# === curl_retry ===
# 统一的下载函数。各参数含义：
#   -f / -L           : 4xx/5xx 时返回非零；自动跟随重定向（GitHub raw / Release 都会跳）
#   --retry 5         : 失败重试 5 次
#   --retry-delay 2   : 每次重试间隔 2 秒（线性，curl 7.84+ 才有指数退避，这里不依赖）
#   --retry-all-errors: 不仅对传输错误，连 HTTP 5xx / 部分 4xx 也重试
#                       （curl 7.71+；旧版本会忽略这个选项不会报错）
#   --connect-timeout : 单次 TCP 连接超时 10s（防 DNS / 中间网络黑洞）
#   --max-time        : 单次完整请求超时 180s（防超大文件下到一半挂在那里）
curl_retry() {
  curl -fL --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 10 --max-time 180 "$@"
}

# === force_apt_ipv4 ===
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

# === ensure_basic_tools ===
ensure_basic_tools() {
  local install_role="${1:-unknown}"

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

  if [[ "${#missing_tools[@]}" -gt 0 ]]; then
    mapfile -t missing_tools < <(printf '%s\n' "${missing_tools[@]}" | sort -u)

    if need_cmd apt-get; then
      info "检测到缺少工具：${missing_tools[*]}"
      maybe_prompt_apt_proxy_for_client "$install_role"
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

# === gen_guid ===
gen_guid() {
  local u
  u="$(tr '[:lower:]' '[:upper:]' < /proc/sys/kernel/random/uuid)"
  echo "{${u}}"
}

# === download_base_cfg ===
# 用 safer_cd/safer_back 替代裸 cd，避免污染调用方 cwd。
download_base_cfg() {
  local url="$1"
  mkdir -p "$APP_DIR"
  safer_cd "$APP_DIR"
  info "下载基准配置 appsettings.base.json ..."
  if ! curl_retry -sS "$url" -o appsettings.base.json; then
    safer_back
    die "下载失败：$url"
  fi
  safer_back
}

# === check_env_supported ===
check_env_supported() {
  is_root || die "请使用 root 身份执行本脚本，例如：sudo bash $0"
  [[ -f /etc/debian_version ]] || warn "未检测到 /etc/debian_version，系统可能不是标准 Debian/Ubuntu。"
}

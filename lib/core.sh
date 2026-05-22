#!/usr/bin/env bash
# core.sh - 核心工具：日志、交互提示、依赖检查、随机密钥生成

# ---------- 颜色与日志 ----------
if [[ -t 1 ]]; then
  _C_RED=$'\033[0;31m'; _C_GRN=$'\033[0;32m'; _C_YLW=$'\033[0;33m'; _C_RST=$'\033[0m'
else
  _C_RED=""; _C_GRN=""; _C_YLW=""; _C_RST=""
fi

info() { echo "${_C_GRN}[INFO]${_C_RST} $*"; }
warn() { echo "${_C_YLW}[WARN]${_C_RST} $*" >&2; }
die()  { echo "${_C_RED}[ERROR]${_C_RST} $*" >&2; exit 1; }

# ---------- 命令/环境检查 ----------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

has_systemd() { [[ -d /run/systemd/system ]] && need_cmd systemctl; }

check_env_supported() {
  [[ "$(id -u)" -eq 0 ]] || die "请用 root 或 sudo 运行本脚本。"
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux。"
  for c in awk sed grep; do
    need_cmd "$c" || die "缺少基础命令：$c"
  done
}

# ---------- 交互提示 ----------
# prompt VAR "提示语" "默认值"
# 注意：本函数用 `printf -v` 回写调用方变量。调用方传入的变量名不得与本函数内部
# 临时变量（__var/__msg/__def/__ans）同名，否则会写到本函数自己的 local 而非调用方
# 变量，造成"读到的值永远为空"的隐蔽 bug（prompt_port 已据此使用 __pp_* 命名）。
prompt() {
  local __var="$1" __msg="$2" __def="${3:-}" __ans=""
  if [[ -n "$__def" ]]; then
    read -r -p "$__msg [$__def]: " __ans || true
    __ans="${__ans:-$__def}"
  else
    read -r -p "$__msg: " __ans || true
  fi
  printf -v "$__var" '%s' "$__ans"
}

# prompt_port VAR "提示语" "默认值" —— 校验 1-65535
# 注意：内部变量名必须与 prompt() 的内部变量（__var/__msg/__def/__ans）完全不同，
# 否则 prompt 的 `printf -v` 会写到自己的同名 local 而非本函数的变量，导致永远校验失败。
prompt_port() {
  local __pp_var="$1" __pp_msg="$2" __pp_def="${3:-}" __pp_val=""
  while true; do
    prompt __pp_val "$__pp_msg" "$__pp_def"
    if [[ "$__pp_val" =~ ^[0-9]+$ ]] && (( __pp_val >= 1 && __pp_val <= 65535 )); then
      printf -v "$__pp_var" '%s' "$__pp_val"
      return 0
    fi
    warn "端口必须是 1-65535 之间的整数。"
  done
}

# ---------- 网络重试 ----------
# curl_retry <curl 参数...>
curl_retry() {
  need_cmd curl || die "缺少 curl。"
  curl --retry 3 --retry-delay 2 --connect-timeout 10 "$@"
}

# ---------- 随机生成 ----------
# gen_guid -> {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}（大写）
gen_guid() {
  local g=""
  if need_cmd uuidgen; then
    g="$(uuidgen)"
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then
    g="$(cat /proc/sys/kernel/random/uuid)"
  else
    g="$(printf '%08x-%04x-%04x-%04x-%012x' \
      $((RANDOM*RANDOM)) $((RANDOM)) $((RANDOM)) $((RANDOM)) $((RANDOM*RANDOM*RANDOM)))"
  fi
  printf '{%s}' "$(echo "$g" | tr '[:lower:]' '[:upper:]')"
}

# gen_secret [长度=24] -> 适合做 protocol-key/transport-key 的随机串（去掉易混淆字符）
gen_secret() {
  local len="${1:-24}"
  if need_cmd openssl; then
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$len"
  else
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len"
  fi
  echo
}

# gen_password [长度=20] -> SOCKS5/代理密码
gen_password() { gen_secret "${1:-20}"; }

# gen_int -> 随机正整数（用于 key.kf 等数值种子）
gen_int() {
  if need_cmd shuf; then
    shuf -i 100000000-999999999 -n 1
  else
    echo $(( (RANDOM<<15 | RANDOM) % 900000000 + 100000000 ))
  fi
}

# ---------- 基础依赖 ----------
# ensure_pkgs <pkg...> —— 在 Debian/Ubuntu 上安装缺失的依赖
ensure_pkgs() {
  local need=() p
  for p in "$@"; do
    case "$p" in
      jq)              need_cmd jq        || need+=(jq) ;;
      curl)            need_cmd curl      || need+=(curl) ;;
      openssl)         need_cmd openssl   || need+=(openssl) ;;
      unzip)           need_cmd unzip     || need+=(unzip) ;;
      uuidgen|uuid-runtime)
                       need_cmd uuidgen   || need+=(uuid-runtime) ;;
      ip|iproute2)     need_cmd ip        || need+=(iproute2) ;;
      ca-certificates) # 不是命令，按文件/目录是否存在判断
                       [[ -e /etc/ssl/certs/ca-certificates.crt || -d /etc/ssl/certs ]] \
                         || need+=(ca-certificates) ;;
      *)               need_cmd "$p"      || need+=("$p") ;;
    esac
  done
  [[ ${#need[@]} -eq 0 ]] && return 0
  if need_cmd apt-get; then
    info "安装依赖：${need[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${need[@]}" \
      || warn "部分依赖安装失败：${need[*]}（请手动安装）"
  elif need_cmd dnf; then
    info "安装依赖：${need[*]}"
    dnf install -y "${need[@]}" >/dev/null 2>&1 || warn "部分依赖安装失败：${need[*]}"
  elif need_cmd yum; then
    info "安装依赖：${need[*]}"
    yum install -y "${need[@]}" >/dev/null 2>&1 || warn "部分依赖安装失败：${need[*]}"
  else
    warn "未识别的包管理器，请手动安装：${need[*]}"
  fi
}

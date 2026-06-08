#!/usr/bin/env bash
# core.sh - 核心工具：日志、交互提示、依赖检查、随机密钥生成

# ---------- 颜色与日志 ----------
if [[ -t 1 ]]; then
  _C_RED=$'\033[0;31m'
  _C_GRN=$'\033[0;32m'
  _C_YLW=$'\033[0;33m'
  _C_RST=$'\033[0m'
else
  _C_RED=""
  _C_GRN=""
  _C_YLW=""
  _C_RST=""
fi

info() { echo "${_C_GRN}[INFO]${_C_RST} $*"; }
warn() { echo "${_C_YLW}[WARN]${_C_RST} $*" >&2; }
die() {
  echo "${_C_RED}[ERROR]${_C_RST} $*" >&2
  exit 1
}

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

# ---------- 输入/路径校验 ----------
# 配置文件名：必须形如 appsettings*.json，且不含路径分隔符 / 注册表分隔符 / 空白，
# 防止 ../../x.json 之类路径穿越，或破坏 compose 卷挂载与 .instances 注册表。
validate_cfg_name() {
  local n="$1"
  [[ -n "$n" ]] || die "配置文件名不能为空。"
  [[ "$n" != *"/"* && "$n" != *"|"* && "$n" != *" "* ]] || die "配置文件名不能包含 / 、| 或空格：$n"
  [[ "$n" =~ ^appsettings[A-Za-z0-9._-]*\.json$ ]] || die "配置文件名不合法（须形如 appsettings.json / appsettings-foo.json）：$n"
}

# 服务名（容器名/compose service 名）：Docker 命名规则的安全子集，且禁止注册表分隔符 |。
validate_service_name() {
  local n="$1"
  [[ -n "$n" ]] || die "服务名不能为空。"
  [[ "$n" != *"|"* ]] || die "服务名不能包含 |：$n"
  [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "服务名不合法（仅允许字母数字与 _ . -，且不以符号开头）：$n"
}

# APP_DIR 安全校验：必须是非空绝对路径，且不是根/系统关键目录，
# 以免 APP_DIR 被环境变量误设后 rm -rf 误删系统目录。
validate_app_dir() {
  local d="${APP_DIR:-}"
  [[ -n "$d" ]] || die "APP_DIR 不能为空。"
  [[ "$d" == /* ]] || die "APP_DIR 必须是绝对路径：$d"
  [[ "$d" != *".."* ]] || die "APP_DIR 不能包含 ..：$d"
  case "$d" in
    / | /bin | /boot | /dev | /etc | /home | /lib | /lib64 | /proc | /root | /run | /sbin | /srv | /sys | /tmp | /usr | /var | /opt | /mnt | /media)
      die "APP_DIR 路径过于危险，拒绝操作：$d"
      ;;
  esac
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
    if [[ "$__pp_val" =~ ^[0-9]+$ ]] && ((__pp_val >= 1 && __pp_val <= 65535)); then
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
      $((RANDOM * RANDOM)) $((RANDOM)) $((RANDOM)) $((RANDOM)) $((RANDOM * RANDOM * RANDOM)))"
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
    echo $(((RANDOM << 15 | RANDOM) % 900000000 + 100000000))
  fi
}

# ---------- 基础依赖 ----------
# ensure_pkgs <pkg...> —— 在 Debian/Ubuntu 上安装缺失的依赖
ensure_pkgs() {
  local need=() p
  for p in "$@"; do
    case "$p" in
      jq) need_cmd jq || need+=(jq) ;;
      curl) need_cmd curl || need+=(curl) ;;
      openssl) need_cmd openssl || need+=(openssl) ;;
      unzip) need_cmd unzip || need+=(unzip) ;;
      uuidgen | uuid-runtime)
        need_cmd uuidgen || need+=(uuid-runtime)
        ;;
      ip | iproute2) need_cmd ip || need+=(iproute2) ;;
      ca-certificates) # 不是命令，按文件/目录是否存在判断
        [[ -e /etc/ssl/certs/ca-certificates.crt || -d /etc/ssl/certs ]] ||
          need+=(ca-certificates)
        ;;
      *) need_cmd "$p" || need+=("$p") ;;
    esac
  done
  [[ ${#need[@]} -eq 0 ]] && return 0
  if need_cmd apt-get; then
    info "安装依赖：${need[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${need[@]}" ||
      warn "部分依赖安装失败：${need[*]}（请手动安装）"
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

# ---------- 持久化可调参数 ----------
# 把本次安装选定的可调参数写入 ${ENV_FILE}（默认 ${APP_DIR}/.env，权限 600），
# 供 systemd 自动更新 / 脚本自更新等"无人值守重新生成 systemd 助手"的场景复用。
# config.sh 在加载时会读取该文件（仅填充未显式设置的变量，显式 env 始终优先）。
persist_env_file() {
  mkdir -p "$APP_DIR"
  {
    echo "# openppp2 持久化配置（由安装脚本自动生成）。"
    echo "# 用途：自动更新/脚本自更新在无人值守地重新生成 systemd 助手时复用这些选项。"
    echo "# 可手工编辑；键名须为大写字母/数字/下划线，值不要带引号。"
    printf '%s=%s\n' LOG_MAX_SIZE "$LOG_MAX_SIZE"
    printf '%s=%s\n' LOG_MAX_FILE "$LOG_MAX_FILE"
    printf '%s=%s\n' MEM_LIMIT "$MEM_LIMIT"
    printf '%s=%s\n' PIDS_LIMIT "$PIDS_LIMIT"
    printf '%s=%s\n' CPUS "$CPUS"
    printf '%s=%s\n' IMAGE_KEEP "$IMAGE_KEEP"
    printf '%s=%s\n' AUTO_ROLLBACK "$AUTO_ROLLBACK"
    printf '%s=%s\n' NOTIFY_WEBHOOK "$NOTIFY_WEBHOOK"
    printf '%s=%s\n' NOTIFY_EMAIL "$NOTIFY_EMAIL"
    printf '%s=%s\n' SELF_UPDATE "$SELF_UPDATE"
    printf '%s=%s\n' DEFAULT_ONCAL "$DEFAULT_ONCAL"
    printf '%s=%s\n' PPP_LOG_MAX_MB "$PPP_LOG_MAX_MB"
    printf '%s=%s\n' PPP_LOG_KEEP "$PPP_LOG_KEEP"
    printf '%s=%s\n' PPP_LOG_ROTATE_ONCAL "$PPP_LOG_ROTATE_ONCAL"
    printf '%s=%s\n' DEFAULT_BOOT_DELAY "$DEFAULT_BOOT_DELAY"
  } >"$ENV_FILE"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  info "已持久化配置到 ${ENV_FILE}（自动更新/自更新将复用这些选项）。"
}

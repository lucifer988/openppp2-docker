#!/usr/bin/env bash
# config.sh — 全局常量与默认值（被所有模块 source）
#
# v2.3 防卡死改动：
#   - 新增全局超时常量 NET_TIMEOUT / APT_TIMEOUT / DOCKER_PULL_TIMEOUT / HEALTH_GRACE_SEC
#   - 新增 NONINTERACTIVE 检测：管道 / 无 TTY 时自动跳过所有交互 prompt
#   - 新增 ALLOW_LOCAL_BUILD：远程镜像不可用时自动本地构建

# ===== 脚本版本 =====
SCRIPT_VERSION="2.3.0"

# ===== 路径 =====
APP_DIR="/opt/openppp2"
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
SECCOMP_FILE="${APP_DIR}/seccomp-openppp2.json"
BACKUP_DIR="${APP_DIR}/backups"

# ===== 镜像与版本管理 =====
# 三种覆盖方式：
#   1) 部署前 export OPENPPP2_IMAGE_TAG=1.0.0.26016
#   2) 安装时交互输入完整镜像地址
#   3) 直接编辑 /opt/openppp2/docker-compose.yml
DEFAULT_IMAGE_REPO="${OPENPPP2_IMAGE_REPO:-ghcr.io/lucifer988/openppp2}"
DEFAULT_IMAGE_TAG="${OPENPPP2_IMAGE_TAG:-latest}"
DEFAULT_IMAGE="${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}"

# 远端镜像若不存在 / 拉不下来，是否允许在本机用 Dockerfile 现场构建
# 这是防卡死的关键：CI 没跑过的仓库直接 pull 会等很久
ALLOW_LOCAL_BUILD="${ALLOW_LOCAL_BUILD:-yes}"

# 配置文件 URL
DEFAULT_BASE_CFG_URL="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"

# ===== 自动更新（systemd timer）=====
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

# ===== 网络默认值 =====
DEFAULT_CLIENT_NIC="${DEFAULT_CLIENT_NIC:-ens192}"
DEFAULT_BOOT_DELAY="${DEFAULT_BOOT_DELAY:-20}"
STRICT_BOOT_DELAY_MODE="${STRICT_BOOT_DELAY_MODE:-no}"

# ===== 资源限制（compose.sh 会引用；用户可在外部覆盖）=====
OPENPPP2_MEM_LIMIT="${OPENPPP2_MEM_LIMIT:-512M}"
OPENPPP2_MEM_RESERVE="${OPENPPP2_MEM_RESERVE:-64M}"
OPENPPP2_CPU_LIMIT="${OPENPPP2_CPU_LIMIT:-1.0}"

# ============================================================
# v2.3 新增：全局超时与防卡死开关
# ============================================================

# 单次网络请求最大耗时（curl --max-time）
NET_TIMEOUT="${NET_TIMEOUT:-60}"
# curl 单次连接超时
NET_CONNECT_TIMEOUT="${NET_CONNECT_TIMEOUT:-10}"

# apt-get update / install 总超时
APT_TIMEOUT="${APT_TIMEOUT:-180}"

# docker pull 总超时（单镜像）
DOCKER_PULL_TIMEOUT="${DOCKER_PULL_TIMEOUT:-300}"

# docker compose pull 总超时（整个 stack）
COMPOSE_PULL_TIMEOUT="${COMPOSE_PULL_TIMEOUT:-600}"

# docker compose up -d 总超时
COMPOSE_UP_TIMEOUT="${COMPOSE_UP_TIMEOUT:-180}"

# 健康检查等待时长（v2.2 是 60s 阻塞，v2.3 降到 20s 并加进度条）
HEALTH_GRACE_SEC="${HEALTH_GRACE_SEC:-20}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-40}"

# 是否输出 set -x 调试信息
OPENPPP2_DEBUG="${OPENPPP2_DEBUG:-0}"

# ============================================================
# v2.3 新增：非交互模式检测
# 如果 stdin 不是 tty（脚本通过 curl | bash 或 ssh 管道运行），
# 所有 prompt 自动使用默认值，避免阻塞。
# 用户可显式 OPENPPP2_NONINTERACTIVE=1/0 覆盖。
# ============================================================
if [[ -n "${OPENPPP2_NONINTERACTIVE:-}" ]]; then
  NONINTERACTIVE="$OPENPPP2_NONINTERACTIVE"
elif [[ ! -t 0 ]]; then
  NONINTERACTIVE=1
else
  NONINTERACTIVE=0
fi

# ===== 运行时状态 =====
COMPOSE_KIND=""
APT_PROXY_PROMPTED=0

# 启用调试时打开 xtrace
if [[ "$OPENPPP2_DEBUG" == "1" ]]; then
  export PS4='+ [$(date +%T)] ${BASH_SOURCE##*/}:${LINENO}: '
  set -x
fi

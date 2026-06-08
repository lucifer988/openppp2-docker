#!/usr/bin/env bash
# config.sh - 默认配置集中管理

# 脚本版本
SCRIPT_VERSION="2.5.0"

# 应用目录（早于其余可调项定义，便于后面加载持久化配置）
APP_DIR="${APP_DIR:-/opt/openppp2}"

# 持久化配置：安装时把本次选定的可调参数写入 ${APP_DIR}/.env，
# 供 systemd 自动更新 / 脚本自更新等"无人值守重新生成"场景复用（见 systemd.sh）。
# 规则：仅填充"尚未由命令行/环境显式设置"的变量，保证显式 env 始终优先于 .env。
if [[ -f "${APP_DIR}/.env" ]]; then
  while IFS='=' read -r _k _v || [[ -n "$_k" ]]; do
    [[ "$_k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue # 跳过注释/空行/非法键
    [[ -n "${!_k+x}" ]] && continue                # 已显式设置则不覆盖
    printf -v "$_k" '%s' "$_v"
  done <"${APP_DIR}/.env"
  unset _k _v
fi

# 本仓库的固定下载基准（tag）。安装脚本、基准配置、兜底 Dockerfile 等所有"从本仓库下载"
# 的动作都锚定到这个 tag，而不是 main 分支，保证可复现、可审计。
# 可用环境变量 OPENPPP2_REF 覆盖（例如临时指向某个 tag/commit 调试）。
# 注意：install_openppp2.sh 自举阶段（在 source 本文件之前）也有一份同名默认值，二者需一致。
REPO_REF="${OPENPPP2_REF:-v2.4.0}"
REPO_RAW_BASE="https://raw.githubusercontent.com/lucifer988/openppp2-docker/${REPO_REF}"
# 本仓库标识（脚本自更新查询最新 release tag 用）
SELF_REPO="${SELF_REPO:-lucifer988/openppp2-docker}"

# 派生路径
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
SECCOMP_FILE="${APP_DIR}/seccomp-openppp2.json"
BACKUP_DIR="${APP_DIR}/backups"
# 服务端随机生成的密钥/参数会写到这里，便于复制到客户端
CREDENTIALS_FILE="${APP_DIR}/server-credentials.txt"
# 持久化可调参数文件
ENV_FILE="${APP_DIR}/.env"

# Docker 安装镜像源（核心：解决国内 download.docker.com 慢/不通导致"卡在安装 Docker"的问题）。
# get.docker.com 官方脚本支持 --mirror，把重头的安装包从国内镜像拉取，避免卡死：
#   auto            -> 自动探测：能快速连通 download.docker.com 就用官方源，否则改用 Aliyun 镜像（默认，推荐）
#   Aliyun          -> 强制用阿里云镜像（https://mirrors.aliyun.com/docker-ce）
#   AzureChinaCloud -> 强制用 Azure 中国镜像（https://mirror.azure.cn/docker-ce）
#   none            -> 强制用官方源（download.docker.com），不使用任何镜像
DOCKER_INSTALL_MIRROR="${DOCKER_INSTALL_MIRROR:-auto}"

# 单次 Docker 安装尝试的超时（秒）。get.docker.com 脚本内部会跑 apt/yum 从远端下载包，
# 网络差时可能长时间无响应；超时后中止本次尝试并换下一种方式/镜像，避免整个一键脚本卡死。
# 留空或设为 0 表示不限时（不建议，网络差时会一直卡住）。
DOCKER_INSTALL_TIMEOUT="${DOCKER_INSTALL_TIMEOUT:-300}"

# Docker 镜像（用户可在安装时改写；这是"浮动标签/发现通道"，compose 实际会固定到其 digest）
DEFAULT_IMAGE="ghcr.io/lucifer988/openppp2:latest"

# 容器日志大小限制（docker json-file 驱动按 max-size 滚动、最多保留 max-file 个，
# 旧日志自动删除，无需任何手动/交互操作。可用环境变量覆盖）
LOG_MAX_SIZE="${LOG_MAX_SIZE:-10m}"
LOG_MAX_FILE="${LOG_MAX_FILE:-3}"

# 运行时资源上限（防止异常实例拖垮宿主机；任一项留空=不限制该项。可用环境变量覆盖）
#   注意：openppp2 是多线程程序，线程也计入 pids，PIDS_LIMIT 不要设得过低，否则会被内核杀。
MEM_LIMIT="${MEM_LIMIT:-1g}"     # 内存上限，如 512m / 1g / 2g；空=不限
PIDS_LIMIT="${PIDS_LIMIT:-4096}" # 进程/线程数上限；空=不限
CPUS="${CPUS:-}"                 # CPU 配额，如 "1.5"；默认空=不限（避免限制代理吞吐）

# 镜像固定与保留：
#   - compose 的 image 固定到不可变 digest（repo@sha256:...），保证 boot/轮转重建不漂移、可复现；
#   - .image_channel 记录浮动标签（如 :latest），自动更新据此"发现"上游新版本；
#   - 更新流程：拉取 channel -> 解析新 digest -> 切换并健康检查 -> 通过则重新固定，否则回滚旧 digest。
IMAGE_KEEP="${IMAGE_KEEP:-2}" # 本机保留的 openppp2 镜像份数（当前+上一个供回滚），其余自动清理；<1 视为不清理

# 自动更新失败通知（systemd OnFailure 触发）。二者都留空则仅写 journald 日志。
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}" # 失败时 POST JSON 到该 URL（企业微信/Slack/飞书等机器人）
NOTIFY_EMAIL="${NOTIFY_EMAIL:-}"     # 失败时发邮件到该地址（需宿主机已有可用的 mail 命令）

# 脚本自更新（默认关闭）。开启后，每周更新任务会先检查本仓库是否有更新的 release tag：
#   有则下载（锚定到该 tag 的 tarball）并仅刷新 systemd 助手脚本/单元（不动配置与容器）。
#   ⚠ 这会让 root 自动执行从公网下载的新脚本，请自行评估供应链风险后再开启（SELF_UPDATE=yes）。
SELF_UPDATE="${SELF_UPDATE:-no}"

# 服务端 ppp.log 文件日志的自动轮转（systemd 定时检查；客户端不写文件日志，不涉及）
#   openppp2 一直占着该文件句柄且非 append 写入，原地截断会留下稀疏文件，
#   因此用「归档 + 重建容器」的方式彻底清零（重建容器 = 全新可写层 = ppp.log 归零）。
PPP_LOG_MAX_MB="${PPP_LOG_MAX_MB:-200}"               # ppp.log 超过此大小(MB)即归档并重建容器
PPP_LOG_KEEP="${PPP_LOG_KEEP:-5}"                     # 宿主机保留的历史归档份数，超出自动删除
PPP_LOG_ROTATE_ONCAL="${PPP_LOG_ROTATE_ONCAL:-daily}" # 检查频率（systemd OnCalendar 语法）

# 上游项目（本地兜底构建时拉取 release zip 用）
UPSTREAM_REPO="liulilittle/openppp2"
# 兜底构建时使用的固定上游版本（GHCR 不可用且无法查询最新版时使用）
FALLBACK_UPSTREAM_TAG="${FALLBACK_UPSTREAM_TAG:-1.0.0.26151}"
# 上述固定版本 openppp2-linux-amd64-simd.zip 的 SHA256；用固定版本兜底构建时校验完整性。
# 若 build_image_local 改用"查询到的最新版"，则 sha 未知，会留空跳过校验（见 docker.sh）。
FALLBACK_UPSTREAM_SHA256="${FALLBACK_UPSTREAM_SHA256:-8718483672c9cab36fedd3ebdb233600d967aba9452a074af6a8620473639d29}"

# 配置文件 URL（download_base_cfg 优先用脚本同目录的本地副本，失败再用这个）
# 锚定到固定 tag，避免 main 漂移。
DEFAULT_BASE_CFG_URL="${REPO_RAW_BASE}/appsettings.base.json"

# 自动更新时间（systemd timer）
DEFAULT_ONCAL="${DEFAULT_ONCAL:-Sun *-*-* 03:00:00}"

# 默认客户端网卡
DEFAULT_CLIENT_NIC="${DEFAULT_CLIENT_NIC:-ens192}"

# 开机延迟（秒）
DEFAULT_BOOT_DELAY="${DEFAULT_BOOT_DELAY:-20}"

# 严格开机延迟模式
STRICT_BOOT_DELAY_MODE="${STRICT_BOOT_DELAY_MODE:-no}"

# 健康检查参数
HEALTH_RETRIES="${HEALTH_RETRIES:-10}"
HEALTH_INTERVAL="${HEALTH_INTERVAL:-3}"

# 自动更新失败回滚开关（yes=更新后健康检查失败自动回滚到旧镜像）
AUTO_ROLLBACK="${AUTO_ROLLBACK:-yes}"

# 运行时状态
COMPOSE_KIND=""
APT_PROXY_PROMPTED=0

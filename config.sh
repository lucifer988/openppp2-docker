#!/usr/bin/env bash
# config.sh - 默认配置集中管理

# 脚本版本
SCRIPT_VERSION="2.3.0"

# 本仓库的固定下载基准（tag）。安装脚本、基准配置、兜底 Dockerfile 等所有"从本仓库下载"
# 的动作都锚定到这个 tag，而不是 main 分支，保证可复现、可审计。
# 可用环境变量 OPENPPP2_REF 覆盖（例如临时指向某个 tag/commit 调试）。
# 注意：install_openppp2.sh 自举阶段（在 source 本文件之前）也有一份同名默认值，二者需一致。
REPO_REF="${OPENPPP2_REF:-v2.3.0}"
REPO_RAW_BASE="https://raw.githubusercontent.com/lucifer988/openppp2-docker/${REPO_REF}"

# 应用目录
APP_DIR="/opt/openppp2"

# 派生路径
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
SECCOMP_FILE="${APP_DIR}/seccomp-openppp2.json"
BACKUP_DIR="${APP_DIR}/backups"
# 服务端随机生成的密钥/参数会写到这里，便于复制到客户端
CREDENTIALS_FILE="${APP_DIR}/server-credentials.txt"

# Docker 镜像
DEFAULT_IMAGE="ghcr.io/lucifer988/openppp2:latest"

# 容器日志大小限制（docker json-file 驱动按 max-size 滚动、最多保留 max-file 个，
# 旧日志自动删除，无需任何手动/交互操作。可用环境变量覆盖）
LOG_MAX_SIZE="${LOG_MAX_SIZE:-10m}"
LOG_MAX_FILE="${LOG_MAX_FILE:-3}"

# 服务端 ppp.log 文件日志的自动轮转（systemd 定时检查；客户端不写文件日志，不涉及）
#   openppp2 一直占着该文件句柄且非 append 写入，原地截断会留下稀疏文件，
#   因此用「归档 + 重建容器」的方式彻底清零（重建容器 = 全新可写层 = ppp.log 归零）。
PPP_LOG_MAX_MB="${PPP_LOG_MAX_MB:-200}"            # ppp.log 超过此大小(MB)即归档并重建容器
PPP_LOG_KEEP="${PPP_LOG_KEEP:-5}"                  # 宿主机保留的历史归档份数，超出自动删除
PPP_LOG_ROTATE_ONCAL="${PPP_LOG_ROTATE_ONCAL:-daily}"  # 检查频率（systemd OnCalendar 语法）

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
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

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

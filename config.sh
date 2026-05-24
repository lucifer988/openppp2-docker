#!/usr/bin/env bash
# config.sh - 默认配置集中管理

# 脚本版本
SCRIPT_VERSION="2.2.0"

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

# 上游项目（本地兜底构建时拉取 release zip 用）
UPSTREAM_REPO="liulilittle/openppp2"
# 兜底构建时使用的固定上游版本（GHCR 不可用且无法查询最新版时使用）
FALLBACK_UPSTREAM_TAG="${FALLBACK_UPSTREAM_TAG:-1.0.0.26016}"

# 配置文件 URL（download_base_cfg 优先用脚本同目录的本地副本，失败再用这个）
DEFAULT_BASE_CFG_URL="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"

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

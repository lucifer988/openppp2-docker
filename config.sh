#!/usr/bin/env bash
# config.sh - 默认配置集中管理

# 应用目录
APP_DIR="/opt/openppp2"

# 派生路径
COMPOSE_FILE="${APP_DIR}/docker-compose.yml"
SECCOMP_FILE="${APP_DIR}/seccomp-openppp2.json"
BACKUP_DIR="${APP_DIR}/backups"

# Docker 镜像
DEFAULT_IMAGE="ghcr.io/lucifer988/openppp2:latest"

# 配置文件 URL
DEFAULT_BASE_CFG_URL="https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/appsettings.base.json"

# 自动更新时间（systemd timer）
DEFAULT_ONCAL="Sun *-*-* 03:00:00"

# 默认客户端网卡
DEFAULT_CLIENT_NIC="${DEFAULT_CLIENT_NIC:-ens192}"

# 开机延迟（秒）
DEFAULT_BOOT_DELAY="${DEFAULT_BOOT_DELAY:-20}"

# 严格开机延迟模式
STRICT_BOOT_DELAY_MODE="${STRICT_BOOT_DELAY_MODE:-no}"

# 运行时状态
COMPOSE_KIND=""
APT_PROXY_PROMPTED=0
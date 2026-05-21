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

# ============================================================
# 镜像与版本管理（点 9）
# ============================================================
# DEFAULT_IMAGE_REPO  : 镜像仓库
# DEFAULT_IMAGE_TAG   : 镜像 tag
#   - "latest"        ：跟随上游每周自动更新（默认，省心）
#   - "1.0.0.26016"   ：固定到具体上游版本，重启 / 再部署可重现
#   - "stable"        ：CI 跑过冒烟测试的最近一次 latest 别名（如果你后续加）
#
# 用户可以三种方式覆盖：
#   1) 在执行脚本前导出：export OPENPPP2_IMAGE_TAG=1.0.0.26016
#   2) 安装时交互输入完整镜像地址
#   3) 直接编辑 /opt/openppp2/docker-compose.yml 后 docker compose up -d
# ============================================================
DEFAULT_IMAGE_REPO="${OPENPPP2_IMAGE_REPO:-ghcr.io/lucifer988/openppp2}"
DEFAULT_IMAGE_TAG="${OPENPPP2_IMAGE_TAG:-latest}"
DEFAULT_IMAGE="${DEFAULT_IMAGE_REPO}:${DEFAULT_IMAGE_TAG}"

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

# 资源限制默认值（compose.sh 会引用；用户可在外部覆盖）
OPENPPP2_MEM_LIMIT="${OPENPPP2_MEM_LIMIT:-512M}"
OPENPPP2_MEM_RESERVE="${OPENPPP2_MEM_RESERVE:-64M}"
OPENPPP2_CPU_LIMIT="${OPENPPP2_CPU_LIMIT:-1.0}"

# 运行时状态
COMPOSE_KIND=""
APT_PROXY_PROMPTED=0

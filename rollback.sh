#!/usr/bin/env bash
# rollback.sh - 错误恢复脚本

set -euo pipefail

APP_DIR="/opt/openppp2"
BACKUP_DIR="${APP_DIR}/backups"

source "$(dirname "$0")/utils.sh" 2>/dev/null || true

list_backups() {
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        echo "没有找到备份目录"
        return 1
    fi
    
    echo "可用的备份："
    ls -lht "${BACKUP_DIR}" | tail -n +2
}

restore_latest() {
    local latest=$(ls -t "${BACKUP_DIR}"/*.bak.* 2>/dev/null | head -1)
    if [[ -z "${latest}" ]]; then
        echo "没有找到备份文件"
        return 1
    fi
    
    echo "恢复最新备份: ${latest}"
    restore_backup "${latest}"
}

case "${1:-}" in
    list) list_backups;;
    restore) restore_latest;;
    *) 
        echo "用法: $0 {list|restore}"
        exit 1
        ;;
esac

#!/usr/bin/env bash
# utils.sh - 通用工具函数库

# 日志函数
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${msg}" | tee -a "${LOG_FILE:-/tmp/openppp2.log}"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
}

# Docker 检查（统一函数，减少重复）
check_docker_running() {
    if ! systemctl is-active --quiet docker; then
        return 1
    fi
    return 0
}

ensure_docker_running() {
    if ! check_docker_running; then
        log_info "启动 Docker 服务..."
        systemctl start docker
        sleep 2
        if ! check_docker_running; then
            log_error "Docker 启动失败"
            return 1
        fi
    fi
    return 0
}

# 端口检查（统一函数）
check_port_available() {
    local port="$1"
    if ss -tuln | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 配置文件备份
backup_file() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        local backup="${file}.bak.$(date +%Y%m%d_%H%M%S)"
        cp -a "${file}" "${backup}"
        log_info "备份: ${backup}"
        echo "${backup}"
    fi
}

# 错误恢复
restore_backup() {
    local backup="$1"
    local target="${backup%.bak.*}"
    if [[ -f "${backup}" ]]; then
        cp -a "${backup}" "${target}"
        log_info "恢复: ${target}"
        return 0
    fi
    return 1
}

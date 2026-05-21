#!/usr/bin/env bash
# lib/backup.sh — Modular library for openppp2-docker
# Auto-refactored from install_openppp2.sh

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === do_backup ===
do_backup() {
  if [[ ! -d "$APP_DIR" ]]; then
    die "未检测到 ${APP_DIR}，请先安装再备份。"
  fi

  mkdir -p "$BACKUP_DIR"

  local ts
  ts="$(date +%Y%m%d_%H%M%S)"

  if [[ -f "$COMPOSE_FILE" ]]; then
    cp -a "$COMPOSE_FILE" "$BACKUP_DIR/docker-compose.yml.bak.${ts}"
    info "已备份: $BACKUP_DIR/docker-compose.yml.bak.${ts}"
  fi

  if [[ -f "$SECCOMP_FILE" ]]; then
    cp -a "$SECCOMP_FILE" "$BACKUP_DIR/seccomp-openppp2.json.bak.${ts}"
    info "已备份: $BACKUP_DIR/seccomp-openppp2.json.bak.${ts}"
  fi

  for cfg in "$APP_DIR"/appsettings*.json; do
    if [[ -f "$cfg" ]]; then
      local base
      base="$(basename "$cfg")"
      cp -a "$cfg" "$BACKUP_DIR/${base}.bak.${ts}"
      info "已备份: $BACKUP_DIR/${base}.bak.${ts}"
    fi
  done

  echo "备份完成。"
}


# === do_restore ===
do_restore() {
  if [[ ! -d "$BACKUP_DIR" ]]; then
    die "未找到备份目录：${BACKUP_DIR}"
  fi

  local latest
  latest="$(find "${BACKUP_DIR}" -maxdepth 1 -name "*.bak.*" -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true)"
  if [[ -z "$latest" ]]; then
    die "未找到备份文件。"
  fi

  local ts
  ts="${latest##*.bak.}"
  if [[ -z "$ts" ]]; then
    die "无法解析备份时间戳。"
  fi

  info "恢复时间戳 ${ts} 的全部备份文件..."

  # 检查关键备份文件是否存在
  if ! ls "${BACKUP_DIR}"/docker-compose.yml.bak."${ts}" >/dev/null 2>&1; then
    die "时间戳 ${ts} 的备份不完整：缺少 docker-compose.yml，无法安全恢复。"
  fi

  local count=0
  for f in "${BACKUP_DIR}"/*.bak."${ts}"; do
    [[ -f "$f" ]] || continue
    local target
    target="${f%.bak.*}"
    if [[ ! -s "$f" ]]; then
      warn "备份文件为空，跳过：$f"
      continue
    fi
    cp -a "$f" "$target"
    echo "已恢复：$target"
    count=$((count + 1))
  done

  if [[ "$count" -eq 0 ]]; then
    die "未找到时间戳为 ${ts} 的备份文件。"
  fi

  echo "恢复完成（共 ${count} 个文件）。"
}


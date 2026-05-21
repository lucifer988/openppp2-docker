#!/usr/bin/env bash
# lib/backup.sh — 备份与恢复

SCRIPT_DIR_BAK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR_BAK}/config.sh" ]] && source "${SCRIPT_DIR_BAK}/config.sh"

# === do_backup — 备份配置文件到 BACKUP_DIR ===
do_backup() {
  [[ -d "$APP_DIR" ]] || die "未发现 ${APP_DIR}，没有可备份内容"
  mkdir -p "$BACKUP_DIR"

  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local dst="${BACKUP_DIR}/${ts}"
  mkdir -p "$dst"

  info "备份到：${dst}"
  local copied=0
  for f in "$APP_DIR"/appsettings*.json \
           "$APP_DIR"/docker-compose.yml \
           "$APP_DIR"/seccomp-openppp2.json \
           "$APP_DIR"/ip.txt \
           "$APP_DIR"/dns-rules.txt \
           "$APP_DIR"/.role \
           "$APP_DIR"/.client_main_service; do
    if [[ -f "$f" ]]; then
      cp -a "$f" "$dst/" && copied=$((copied+1))
    fi
  done
  info "共备份 ${copied} 个文件"

  # 保留最近 10 份
  local keep=10
  local count
  count="$(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d | wc -l)"
  if [[ "$count" -gt "$keep" ]]; then
    info "备份超过 ${keep} 份，清理最旧的..."
    find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' \
      | sort -n | head -n $((count - keep)) | awk '{print $2}' \
      | xargs -r rm -rf
  fi
}

# === do_restore — 从最新备份恢复 ===
do_restore() {
  [[ -d "$BACKUP_DIR" ]] || die "没有 ${BACKUP_DIR} 目录，无法回滚"

  local latest
  latest="$(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' \
            | sort -nr | head -1 | awk '{print $2}')"
  [[ -z "$latest" ]] && die "${BACKUP_DIR} 下没有任何备份目录"

  info "从最新备份恢复：${latest}"
  local restored=0
  for f in "$latest"/*; do
    [[ -f "$f" ]] || continue
    local name
    name="$(basename "$f")"
    cp -a "$f" "${APP_DIR}/${name}" && restored=$((restored+1))
  done
  info "已恢复 ${restored} 个文件"

  echo
  warn "提示：恢复后建议执行 cd ${APP_DIR} && docker compose up -d 让变更生效"
}

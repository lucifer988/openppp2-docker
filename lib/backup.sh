#!/usr/bin/env bash
# backup.sh - 备份与恢复

do_backup() {
  [[ -d "$APP_DIR" ]] || die "未发现安装目录：$APP_DIR"
  local ts snap
  ts="$(date +%Y%m%d_%H%M%S)"
  snap="${BACKUP_DIR}/${ts}"
  mkdir -p "$snap"

  local n=0
  for f in "$APP_DIR"/appsettings*.json; do
    [[ -e "$f" ]] && { cp -a "$f" "$snap"/ && n=$((n + 1)); }
  done
  [[ -f "$COMPOSE_FILE" ]] && cp -a "$COMPOSE_FILE" "$snap"/ && n=$((n + 1))
  [[ -f "$SECCOMP_FILE" ]] && cp -a "$SECCOMP_FILE" "$snap"/ && n=$((n + 1))
  [[ -f "${APP_DIR}/.instances" ]] && cp -a "${APP_DIR}/.instances" "$snap"/ || true
  [[ -f "${APP_DIR}/.image" ]] && cp -a "${APP_DIR}/.image" "$snap"/ || true
  [[ -f "${APP_DIR}/.image_channel" ]] && cp -a "${APP_DIR}/.image_channel" "$snap"/ || true
  [[ -f "${APP_DIR}/.env" ]] && cp -a "${APP_DIR}/.env" "$snap"/ || true

  info "已备份 ${n} 个文件到：${snap}"
}

# 找到最新备份目录
_latest_backup() {
  [[ -d "$BACKUP_DIR" ]] || return 1
  find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null |
    sort -rn | awk 'NR==1{ $1=""; sub(/^ /,""); print }'
}

do_restore() {
  local snap
  snap="$(_latest_backup)" || die "没有可用备份（${BACKUP_DIR}）。"
  [[ -n "$snap" && -d "$snap" ]] || die "没有可用备份（${BACKUP_DIR}）。"

  info "从最新备份恢复：${snap}"
  cp -a "$snap"/appsettings*.json "$APP_DIR"/ 2>/dev/null || true
  [[ -f "$snap/docker-compose.yml" ]] && cp -a "$snap/docker-compose.yml" "$COMPOSE_FILE"
  [[ -f "$snap/seccomp-openppp2.json" ]] && cp -a "$snap/seccomp-openppp2.json" "$SECCOMP_FILE"
  [[ -f "$snap/.instances" ]] && cp -a "$snap/.instances" "${APP_DIR}/.instances"
  [[ -f "$snap/.image" ]] && cp -a "$snap/.image" "${APP_DIR}/.image"
  [[ -f "$snap/.image_channel" ]] && cp -a "$snap/.image_channel" "${APP_DIR}/.image_channel"
  [[ -f "$snap/.env" ]] && cp -a "$snap/.env" "${APP_DIR}/.env"

  if need_cmd docker; then
    detect_compose >/dev/null 2>&1 || true
    [[ -n "$COMPOSE_KIND" ]] && compose up -d --remove-orphans || true
  fi
  info "恢复完成。"
}

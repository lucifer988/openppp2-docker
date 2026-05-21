#!/usr/bin/env bash
# lib/systemd.sh — systemd 集成（开机延迟启动 + 周更新 + 失败回滚）
#
# v2.3 改动：systemctl enable --now 全部加 30s 超时

SCRIPT_DIR_SYSTEMD="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR_SYSTEMD}/config.sh" ]] && source "${SCRIPT_DIR_SYSTEMD}/config.sh"

# === setup_systemd_boot_delay_start ===
setup_systemd_boot_delay_start() {
  if ! has_systemd; then
    warn "无 systemd，跳过开机延迟启动。"
    return 0
  fi

  local delay="${OPENPPP2_BOOT_DELAY:-$DEFAULT_BOOT_DELAY}"
  if ! [[ "$delay" =~ ^[0-9]+$ ]]; then
    warn "OPENPPP2_BOOT_DELAY 非数字：${delay}，回退为 ${DEFAULT_BOOT_DELAY}"
    delay="$DEFAULT_BOOT_DELAY"
  fi

  if [[ "$delay" -le 0 ]]; then
    info "OPENPPP2_BOOT_DELAY=${delay}：禁用开机延迟启动"
    timeout 15 systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/openppp2-boot.service \
          /usr/local/bin/openppp2-wait-uptime.sh \
          /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
    timeout 10 systemctl daemon-reload >/dev/null 2>&1 || true
    return 0
  fi

  cat >/usr/local/bin/openppp2-wait-uptime.sh <<'WAITEOF'
#!/usr/bin/env bash
set -euo pipefail
delay="${1:-20}"
if ! [[ "$delay" =~ ^[0-9]+$ ]]; then delay=20; fi
up="$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
if [[ "$up" -lt "$delay" ]]; then
  sleep $(( delay - up ))
fi
WAITEOF
  chmod +x /usr/local/bin/openppp2-wait-uptime.sh

  cat >/usr/local/bin/openppp2-stack.sh <<'STACKEOF'
#!/usr/bin/env bash
set -euo pipefail

cd /opt/openppp2 2>/dev/null || exit 0
[[ -f docker-compose.yml ]] || exit 0

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

case "${1:-start}" in
  start)   "${dc[@]}" up -d --remove-orphans ;;
  stop)    "${dc[@]}" down --remove-orphans || true ;;
  restart) "${dc[@]}" down --remove-orphans || true; "${dc[@]}" up -d --remove-orphans ;;
  *)       echo "usage: $0 {start|stop|restart}" >&2; exit 2 ;;
esac
STACKEOF
  chmod +x /usr/local/bin/openppp2-stack.sh

  cat >/etc/systemd/system/openppp2-boot.service <<SERVICEEOF
[Unit]
Description=Delayed start openppp2 stack (wait uptime >= ${delay}s)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/local/bin/openppp2-wait-uptime.sh ${delay}
ExecStart=/usr/local/bin/openppp2-stack.sh start
ExecStop=/usr/local/bin/openppp2-stack.sh stop
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
SERVICEEOF

  timeout 15 systemctl daemon-reload || warn "daemon-reload 超时"
  timeout 30 systemctl enable --now openppp2-boot.service || warn "enable openppp2-boot.service 超时"
  info "已启用 openppp2-boot.service：开机后等 uptime≥${delay}s 再启动"
}

# === setup_systemd_weekly_update ===
setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "无 systemd，跳过定时更新"
    return 0
  fi

  echo
  info "设置 systemd 每周自动更新（带健康检查 + 失败回滚）"
  local oncal
  prompt oncal "请输入 OnCalendar 表达式（按周）" "${DEFAULT_ONCAL}"

  cat >/usr/local/bin/openppp2-update.sh <<'UPDATEEOF'
#!/usr/bin/env bash
# openppp2-update.sh — 周期触发的自动更新脚本（带健康检查 + 失败回滚）
# 退出码：0=成功 / 1=更新失败已回滚 / 2=回滚也失败需人工介入

set -euo pipefail

APP_DIR="/opt/openppp2"
LOG_FILE="/var/log/openppp2-update.log"
DIGEST_STATE="${APP_DIR}/.last_image_digests"
HEALTH_GRACE_SEC="${HEALTH_GRACE_SEC:-30}"

cd "$APP_DIR" 2>/dev/null || exit 0
[[ -f docker-compose.yml ]] || exit 0

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] $*" | tee -a "$LOG_FILE" >&2; }

[[ -f /etc/default/openppp2-update ]] && . /etc/default/openppp2-update || true

notify() {
  local status="$1" detail="$2"
  if [[ -n "${OPENPPP2_UPDATE_WEBHOOK:-}" ]]; then
    local url="${OPENPPP2_UPDATE_WEBHOOK//\{title\}/openppp2-${status}}"
    url="${url//\{body\}/$(echo "$detail" | tr ' ' '+' | head -c 200)}"
    curl -fsSL --max-time 10 "$url" >/dev/null 2>&1 || true
  fi
}

record_digests() {
  local target="$1"
  : > "$target"
  local svcs s cid digest
  svcs="$("${dc[@]}" config --services 2>/dev/null || true)"
  for s in $svcs; do
    cid="$(docker ps -a --filter "name=^${s}$" --format '{{.ID}}' | head -1 || true)"
    [[ -z "$cid" ]] && continue
    digest="$(docker inspect --format '{{.Image}}' "$cid" 2>/dev/null || true)"
    [[ -z "$digest" ]] && continue
    echo "${s}=${digest}" >> "$target"
  done
}

check_health() {
  local svcs s status running bad=0
  svcs="$("${dc[@]}" config --services 2>/dev/null || true)"
  for s in $svcs; do
    running="$(docker inspect --format '{{.State.Running}}' "$s" 2>/dev/null || echo false)"
    if [[ "$running" != "true" ]]; then
      log "  ✗ ${s}: 未运行"; bad=1; continue
    fi
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$s" 2>/dev/null || true)"
    if [[ "$status" == "unhealthy" ]]; then
      log "  ✗ ${s}: unhealthy"; bad=1; continue
    fi
    if docker logs --tail 200 "$s" 2>&1 | grep -q 'io_uring_queue_init: Operation not permitted'; then
      log "  ✗ ${s}: seccomp 拒绝 io_uring"; bad=1; continue
    fi
    log "  ✓ ${s}: ${status}"
  done
  return $bad
}

rollback() {
  local state="$1"
  [[ -f "$state" ]] || { log "回滚状态文件不存在：$state"; return 1; }
  log "开始回滚到上一版本镜像..."
  local svc digest current_image
  while IFS='=' read -r svc digest; do
    [[ -z "$svc" || -z "$digest" ]] && continue
    current_image="$(awk -v s="^[[:space:]]{2}${svc}:" '$0 ~ s {found=1; next} found && /image:/ {print $2; exit}' docker-compose.yml)"
    if [[ -n "$current_image" && -n "$digest" ]]; then
      log "  ${svc}: ${digest} -> retag as ${current_image}"
      docker tag "$digest" "$current_image" 2>>"$LOG_FILE" || log "  ⚠ retag 失败"
    fi
  done < "$state"
  "${dc[@]}" up -d --remove-orphans 2>>"$LOG_FILE" || return 1
  sleep "$HEALTH_GRACE_SEC"
  check_health
}

log "================================================"
log "openppp2 自动更新开始"

mkdir -p "$(dirname "$DIGEST_STATE")"
record_digests "$DIGEST_STATE"
log "已记录 $(wc -l <"$DIGEST_STATE" 2>/dev/null || echo 0) 个服务的当前 digest"

if ! timeout 600 "${dc[@]}" pull 2>>"$LOG_FILE"; then
  log "compose pull 失败或超时，本轮不做变更"
  notify "pull-failed" "compose pull failed"
  exit 1
fi

NEW_STATE="$(mktemp)"
record_digests "$NEW_STATE"
if diff -q "$DIGEST_STATE" "$NEW_STATE" >/dev/null 2>&1; then
  log "镜像无更新，跳过重启"
  rm -f "$NEW_STATE"
  exit 0
fi
log "检测到镜像变更，开始滚动重启"
rm -f "$NEW_STATE"

if ! timeout 180 "${dc[@]}" up -d --remove-orphans 2>>"$LOG_FILE"; then
  log "compose up -d 失败/超时，尝试回滚"
  if rollback "$DIGEST_STATE"; then
    log "回滚成功"
    notify "rolled-back" "compose up failed, rolled back ok"
    exit 1
  else
    log "回滚失败，需人工介入"
    notify "FATAL" "compose up failed and rollback failed"
    exit 2
  fi
fi

log "等待 ${HEALTH_GRACE_SEC}s 进入稳态..."
sleep "$HEALTH_GRACE_SEC"

if check_health; then
  log "全部服务健康，更新完成 ✓"
  notify "success" "update ok"
  exit 0
fi

log "健康检查未通过，回滚到旧版本"
if rollback "$DIGEST_STATE"; then
  log "回滚成功 ✓"
  notify "rolled-back" "health check failed, rolled back ok"
  exit 1
else
  log "回滚失败 ✗（人工介入）"
  notify "FATAL" "health check failed and rollback failed"
  exit 2
fi
UPDATEEOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'SERVICEEOF'
[Unit]
Description=Update openppp2 container images (with health-check & rollback)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
EnvironmentFile=-/etc/default/openppp2-update
ExecStart=/usr/local/bin/openppp2-update.sh
SuccessExitStatus=0 1 2
TimeoutStartSec=1200
SERVICEEOF

  cat >/etc/systemd/system/openppp2-update.timer <<TIMEREOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${oncal}
Persistent=true
RandomizedDelaySec=600
Unit=openppp2-update.service

[Install]
WantedBy=timers.target
TIMEREOF

  if [[ ! -f /etc/default/openppp2-update ]]; then
    cat >/etc/default/openppp2-update <<'DEFEOF'
# openppp2 自动更新可选参数
#HEALTH_GRACE_SEC=30
# 通知 Webhook，{title} / {body} 会被替换
#OPENPPP2_UPDATE_WEBHOOK=""
DEFEOF
  fi

  timeout 15 systemctl daemon-reload || warn "daemon-reload 超时"
  timeout 30 systemctl enable --now openppp2-update.timer || warn "enable update.timer 超时"
  info "已启用 openppp2-update.timer（带健康检查 + 失败回滚）"
  info "更新日志：/var/log/openppp2-update.log"
  info "通知配置：/etc/default/openppp2-update"

  setup_systemd_boot_delay_start
}

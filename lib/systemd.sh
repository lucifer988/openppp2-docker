#!/usr/bin/env bash
# lib/systemd.sh — Modular library for openppp2-docker
# Auto-refactored from install_openppp2.sh

# Source config.sh for shared constants (APP_DIR, DEFAULT_IMAGE, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${SCRIPT_DIR}/config.sh" ]] && source "${SCRIPT_DIR}/config.sh"

# === setup_systemd_boot_delay_start ===
setup_systemd_boot_delay_start() {
  if ! has_systemd; then
    warn "无 systemd，跳过开机延迟启动。"
    return 0
  fi

  local delay="${OPENPPP2_BOOT_DELAY:-$DEFAULT_BOOT_DELAY}"
  if ! [[ "$delay" =~ ^[0-9]+$ ]]; then
    warn "OPENPPP2_BOOT_DELAY 非纯数字：${delay}，回退为 ${DEFAULT_BOOT_DELAY}"
    delay="$DEFAULT_BOOT_DELAY"
  fi

  if [[ "$delay" -le 0 ]]; then
    info "OPENPPP2_BOOT_DELAY=${delay}：已禁用开机延迟启动（openppp2-boot.service）"
    systemctl disable --now openppp2-boot.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/openppp2-boot.service \
          /usr/local/bin/openppp2-wait-uptime.sh \
          /usr/local/bin/openppp2-stack.sh >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
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
  start)
    "${dc[@]}" up -d --remove-orphans
    ;;
  stop)
    "${dc[@]}" down --remove-orphans || true
    ;;
  restart)
    "${dc[@]}" down --remove-orphans || true
    "${dc[@]}" up -d --remove-orphans
    ;;
  *)
    echo "usage: $0 {start|stop|restart}" >&2
    exit 2
    ;;
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

  systemctl daemon-reload
  systemctl enable --now openppp2-boot.service
  info "已启用 openppp2-boot.service：开机后等待 uptime≥${delay}s 再启动 openppp2（关机时 down 防抢跑）"
}


# === setup_systemd_weekly_update ===
setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "无 systemd，跳过定时更新。可用 crontab 定时执行 /usr/local/bin/openppp2-update.sh"
    return 0
  fi

  echo
  info "设置 systemd 每周自动更新（pull + up -d）"
  local oncal
  prompt oncal "请输入 OnCalendar（按周）表达式" "${DEFAULT_ONCAL}"

  cat >/usr/local/bin/openppp2-update.sh <<'UPDATEEOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/openppp2

if docker compose version >/dev/null 2>&1; then
  dc=(docker compose)
else
  dc=(docker-compose)
fi

"${dc[@]}" pull
"${dc[@]}" up -d --remove-orphans
UPDATEEOF
  chmod +x /usr/local/bin/openppp2-update.sh

  cat >/etc/systemd/system/openppp2-update.service <<'SERVICEEOF'
[Unit]
Description=Update openppp2 container images
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
SERVICEEOF

  cat >/etc/systemd/system/openppp2-update.timer <<TIMEREOF
[Unit]
Description=Run openppp2 update weekly

[Timer]
OnCalendar=${oncal}
Persistent=true
Unit=openppp2-update.service

[Install]
WantedBy=timers.target
TIMEREOF

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer
  info "已启用 openppp2-update.timer"

  setup_systemd_boot_delay_start
}


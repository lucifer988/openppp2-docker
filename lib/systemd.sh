#!/usr/bin/env bash
# systemd.sh - systemd 集成：每周自动更新（带失败回滚）+ 开机延迟启动

# 生成一个独立可执行的 stack 助手（boot/update 复用，避免依赖 lib）
_write_stack_helper() {
  local kind="$COMPOSE_KIND"
  cat > /usr/local/bin/openppp2-stack.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
cd "\$APP_DIR" || exit 1
case "${kind}" in
  "docker compose") docker compose -f "\$COMPOSE_FILE" "\$@" ;;
  "docker-compose")  docker-compose -f "\$COMPOSE_FILE" "\$@" ;;
  *) echo "compose 未知" >&2; exit 1 ;;
esac
EOF
  chmod +x /usr/local/bin/openppp2-stack.sh
}

# 生成带回滚的更新脚本
_write_update_script() {
  local rollback="$AUTO_ROLLBACK"
  cat > /usr/local/bin/openppp2-update.sh <<EOF
#!/usr/bin/env bash
# openppp2 自动更新（健康检查失败则回滚到旧镜像并恢复配置）
set -uo pipefail
APP_DIR="${APP_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
BACKUP_DIR="${BACKUP_DIR}"
AUTO_ROLLBACK="${rollback}"
STACK=/usr/local/bin/openppp2-stack.sh
LOG() { echo "[\$(date '+%F %T')] \$*"; }

cd "\$APP_DIR" || exit 1
[[ -f "\$COMPOSE_FILE" ]] || { LOG "无 compose 文件，跳过"; exit 0; }

# 当前在跑的 openppp2 容器
mapfile -t CONTS < <(docker ps -a --filter name=openppp2 --format '{{.Names}}')

# 1) 快照旧镜像 ID（按容器记录其镜像，用于回滚重打 tag）
declare -A OLD_IMG_ID OLD_IMG_REF
for c in "\${CONTS[@]}"; do
  OLD_IMG_REF["\$c"]="\$(docker inspect -f '{{.Config.Image}}' "\$c" 2>/dev/null)"
  OLD_IMG_ID["\$c"]="\$(docker inspect -f '{{.Image}}' "\$c" 2>/dev/null)"
done

# 2) 备份配置（用于回滚）
TS="\$(date +%Y%m%d_%H%M%S)"
SNAP="\${BACKUP_DIR}/auto-\${TS}"
mkdir -p "\$SNAP"
cp -a "\$APP_DIR"/appsettings*.json "\$SNAP"/ 2>/dev/null || true
cp -a "\$COMPOSE_FILE" "\$SNAP"/ 2>/dev/null || true
cp -a "\$APP_DIR"/seccomp-openppp2.json "\$SNAP"/ 2>/dev/null || true

# 3) 拉取并启动新镜像
LOG "拉取最新镜像..."
"\$STACK" pull || { LOG "pull 失败，保持现状退出"; exit 0; }
LOG "重新创建容器..."
"\$STACK" up -d --remove-orphans

# 4) 健康检查：容器 Running + ppp 进程
health_ok() {
  local ok=1 c st
  for c in "\${CONTS[@]}"; do
    st="\$(docker inspect -f '{{.State.Running}}' "\$c" 2>/dev/null || echo false)"
    if [[ "\$st" != "true" ]]; then LOG "不健康：\$c 未运行"; ok=0; continue; fi
    if ! docker exec "\$c" sh -c 'pgrep -x ppp >/dev/null 2>&1 || pidof ppp >/dev/null 2>&1'; then
      LOG "不健康：\$c 内无 ppp 进程"; ok=0
    fi
  done
  return \$(( ok == 1 ? 0 : 1 ))
}

LOG "等待服务就绪..."
sleep 8
if health_ok; then
  LOG "更新成功，健康检查通过。"
  exit 0
fi

# 5) 失败回滚
if [[ "\$AUTO_ROLLBACK" != "yes" ]]; then
  LOG "健康检查未通过，且未开启自动回滚（AUTO_ROLLBACK=\$AUTO_ROLLBACK）。请手动检查。"
  exit 1
fi

LOG "健康检查未通过，开始回滚到旧镜像并恢复配置..."
for c in "\${CONTS[@]}"; do
  if [[ -n "\${OLD_IMG_ID[\$c]:-}" && -n "\${OLD_IMG_REF[\$c]:-}" ]]; then
    docker tag "\${OLD_IMG_ID[\$c]}" "\${OLD_IMG_REF[\$c]}" 2>/dev/null || true
  fi
done
# 恢复配置
cp -a "\$SNAP"/appsettings*.json "\$APP_DIR"/ 2>/dev/null || true
cp -a "\$SNAP"/docker-compose.yml "\$COMPOSE_FILE" 2>/dev/null || true
cp -a "\$SNAP"/seccomp-openppp2.json "\$APP_DIR"/ 2>/dev/null || true
"\$STACK" up -d --remove-orphans

if health_ok; then
  LOG "已回滚到旧版本并恢复运行。"
else
  LOG "回滚后仍不健康，请人工介入！"
fi
exit 1
EOF
  chmod +x /usr/local/bin/openppp2-update.sh
}

_write_boot_service() {
  local delay="$DEFAULT_BOOT_DELAY"
  cat > /usr/local/bin/openppp2-wait-uptime.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
TARGET="${delay}"
while :; do
  up="\$(awk '{print int(\$1)}' /proc/uptime)"
  (( up >= TARGET )) && break
  sleep 1
done
exec /usr/local/bin/openppp2-stack.sh up -d --remove-orphans
EOF
  chmod +x /usr/local/bin/openppp2-wait-uptime.sh

  cat > /etc/systemd/system/openppp2-boot.service <<EOF
[Unit]
Description=openppp2 delayed boot start
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-wait-uptime.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "无 systemd，跳过自动更新/开机启动配置。"
    return 0
  fi
  detect_compose >/dev/null 2>&1 || true

  _write_stack_helper
  _write_update_script

  cat > /etc/systemd/system/openppp2-update.service <<EOF
[Unit]
Description=openppp2 auto update (with health-gated rollback)
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
EOF

  cat > /etc/systemd/system/openppp2-update.timer <<EOF
[Unit]
Description=Run openppp2 auto update weekly

[Timer]
OnCalendar=${DEFAULT_ONCAL}
Persistent=true

[Install]
WantedBy=timers.target
EOF

  # 开机延迟启动（可选）
  if [[ "${DEFAULT_BOOT_DELAY}" -gt 0 ]]; then
    _write_boot_service
  fi

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer >/dev/null 2>&1 || true
  if [[ "${DEFAULT_BOOT_DELAY}" -gt 0 ]]; then
    systemctl enable openppp2-boot.service >/dev/null 2>&1 || true
  fi

  info "已配置每周自动更新（${DEFAULT_ONCAL}），失败自动回滚：${AUTO_ROLLBACK}"
}

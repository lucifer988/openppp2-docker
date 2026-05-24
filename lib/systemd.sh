#!/usr/bin/env bash
# systemd.sh - systemd 集成：每周自动更新（带失败回滚）+ 开机延迟启动

# 生成一个独立可执行的 stack 助手（boot/update 复用，避免依赖 lib）
_write_stack_helper() {
  local kind="$COMPOSE_KIND"
  cat >/usr/local/bin/openppp2-stack.sh <<EOF
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
  cat >/usr/local/bin/openppp2-update.sh <<EOF
#!/usr/bin/env bash
# openppp2 自动更新（健康检查失败则回滚到旧镜像并恢复配置）
set -uo pipefail
umask 077   # 备份快照含密钥配置，禁止世界可读
APP_DIR="${APP_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
BACKUP_DIR="${BACKUP_DIR}"
AUTO_ROLLBACK="${rollback}"
STACK=/usr/local/bin/openppp2-stack.sh
LOG() { echo "[\$(date '+%F %T')] \$*"; }

# 串行化：与 logrotate/boot 共用一把锁，避免并发对同一 compose 栈做 pull/recreate 打架。
LOCK="/run/openppp2.lock"
exec 9>"\$LOCK" 2>/dev/null || exec 9>/tmp/openppp2.lock
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { LOG "另一个 openppp2 维护任务正在运行，跳过本次更新。"; exit 0; }
fi

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

# 4) 健康检查：容器 Running + ppp 进程 + 真实出网/监听探测
health_ok() {
  local ok=1 c st bind hport sport
  local egress_url="https://ifconfig.me"
  for c in "\${CONTS[@]}"; do
    st="\$(docker inspect -f '{{.State.Status}}' "\$c" 2>/dev/null || echo missing)"
    if [[ "\$st" != "running" ]]; then LOG "不健康：\$c 状态=\$st（非 running）"; ok=0; continue; fi
    # 若镜像声明了 HEALTHCHECK，必须为 healthy（starting/unhealthy 都判失败）
    hs="\$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "\$c" 2>/dev/null || true)"
    if [[ -n "\$hs" && "\$hs" != "healthy" ]]; then LOG "不健康：\$c HEALTHCHECK=\$hs"; ok=0; continue; fi
    if ! docker exec "\$c" sh -c 'pgrep -x ppp >/dev/null 2>&1 || pidof ppp >/dev/null 2>&1'; then
      LOG "不健康：\$c 内无 ppp 进程"; ok=0; continue
    fi
  done

  # 客户端实例：用注册表里的端口 + 配置里的 bind，做真实代理出网探测
  if [[ -f "\$APP_DIR/.instances" ]] && command -v curl >/dev/null 2>&1; then
    local svc cfg tun tunip tungw nic ngw
    while IFS='|' read -r svc cfg tun tunip tungw nic ngw hport sport _mux; do
      [[ -z "\$svc" ]] && continue
      bind=""
      if command -v jq >/dev/null 2>&1 && [[ -f "\$APP_DIR/\$cfg" ]]; then
        bind="\$(jq -r '.client["http-proxy"].bind // ""' "\$APP_DIR/\$cfg" 2>/dev/null)"
      fi
      [[ -n "\$bind" ]] || continue
      if [[ -n "\$hport" && "\$hport" != "0" ]]; then
        curl -fsS -x "http://\${bind}:\${hport}" --max-time 10 -o /dev/null "\$egress_url" 2>/dev/null \
          || { LOG "不健康：\$svc HTTP 代理出网失败 (\${bind}:\${hport})"; ok=0; }
      fi
      if [[ -n "\$sport" && "\$sport" != "0" ]]; then
        curl -fsS -x "socks5h://\${bind}:\${sport}" --max-time 10 -o /dev/null "\$egress_url" 2>/dev/null \
          || { LOG "不健康：\$svc SOCKS5 代理出网失败 (\${bind}:\${sport})"; ok=0; }
      fi
    done < "\$APP_DIR/.instances"
  fi

  # 服务端：检查容器内 TCP/UDP 监听
  if [[ -f "\$APP_DIR/.role" && "\$(cat "\$APP_DIR/.role" 2>/dev/null)" == "server" ]]; then
    local sport_srv
    sport_srv="\$(jq -r '.tcp.listen.port // 20000' "\$APP_DIR"/appsettings.json 2>/dev/null || echo 20000)"
    for c in "\${CONTS[@]}"; do
      docker exec "\$c" sh -c "ss -ltn 2>/dev/null | grep -q ':\${sport_srv}'" \
        || { LOG "不健康：\$c 未在 \${sport_srv} 监听 TCP"; ok=0; }
      docker exec "\$c" sh -c "ss -lun 2>/dev/null | grep -q ':\${sport_srv}'" \
        || { LOG "不健康：\$c 未在 \${sport_srv} 监听 UDP"; ok=0; }
    done
  fi

  return \$(( ok == 1 ? 0 : 1 ))
}

LOG "等待服务就绪并做健康检查（最多重试 6 次）..."
HC_OK=0
for _i in 1 2 3 4 5 6; do
  sleep 10
  if health_ok; then HC_OK=1; break; fi
  LOG "第 \${_i} 次健康检查未通过，继续等待..."
done
if [[ "\$HC_OK" == "1" ]]; then
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
  cat >/usr/local/bin/openppp2-wait-uptime.sh <<EOF
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

  cat >/etc/systemd/system/openppp2-boot.service <<EOF
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

# 生成服务端 ppp.log 轮转脚本：
#   openppp2 以 O_RDWR（非 append）持有 ppp.log 句柄，原地截断会产生稀疏文件，
#   故超过阈值时「压缩归档到宿主机 + 重建容器（全新可写层）」彻底清零，再清理旧归档。
#   仅服务端写文件日志；客户端 .role!=server 时脚本直接退出。
_write_logrotate_script() {
  cat >/usr/local/bin/openppp2-logrotate.sh <<EOF
#!/usr/bin/env bash
# openppp2 服务端 ppp.log 自动轮转（归档 + 重建容器以彻底清零）
set -uo pipefail
umask 077   # 归档的日志可能含敏感信息，禁止世界可读
APP_DIR="${APP_DIR}"
ARCH_DIR="${APP_DIR}/logs"
CONTAINER="openppp2"
LOG_PATH="/opt/openppp2/ppp.log"
MAX_BYTES=\$(( ${PPP_LOG_MAX_MB} * 1024 * 1024 ))
KEEP=${PPP_LOG_KEEP}
STACK=/usr/local/bin/openppp2-stack.sh
LOG() { echo "[\$(date '+%F %T')] \$*"; }

# 串行化：与 update/boot 共用同一把锁，避免轮转重建容器时与更新并发冲突。
LOCK="/run/openppp2.lock"
exec 9>"\$LOCK" 2>/dev/null || exec 9>/tmp/openppp2.lock
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { LOG "另一个 openppp2 维护任务正在运行，跳过本次轮转。"; exit 0; }
fi

# 仅服务端有文件日志
[[ -f "\$APP_DIR/.role" && "\$(cat "\$APP_DIR/.role" 2>/dev/null)" == "server" ]] || exit 0
command -v docker >/dev/null 2>&1 || exit 0
docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "\$CONTAINER" || exit 0

# 取容器内 ppp.log 当前大小（不存在或异常按 0 处理）
size="\$(docker exec "\$CONTAINER" sh -c "wc -c < '\$LOG_PATH' 2>/dev/null" 2>/dev/null || echo 0)"
size="\${size//[^0-9]/}"; size="\${size:-0}"
if (( size <= MAX_BYTES )); then
  exit 0
fi

mkdir -p "\$ARCH_DIR"
TS="\$(date +%Y%m%d_%H%M%S)"
ARCHIVE="\$ARCH_DIR/ppp-\${TS}.log.gz"
LOG "ppp.log 已达 \${size} 字节（阈值 \${MAX_BYTES}），归档到 \${ARCHIVE} 并重建容器..."

# 1) 压缩归档到宿主机
if ! docker exec "\$CONTAINER" sh -c "cat '\$LOG_PATH'" 2>/dev/null | gzip -c > "\$ARCHIVE"; then
  LOG "归档失败，放弃本次轮转（不重建容器）。"
  rm -f "\$ARCHIVE" 2>/dev/null || true
  exit 1
fi

# 2) 重建容器 → 全新可写层 → ppp.log 彻底清零（openppp2 重新打开文件，几秒内自动拉起）
cd "\$APP_DIR" || exit 1
if ! "\$STACK" up -d --force-recreate --remove-orphans; then
  LOG "重建容器失败，请手动检查（归档已保留：\${ARCHIVE}）。"
  exit 1
fi

# 3) 只保留最近 KEEP 份归档，其余删除
pruned=0
while IFS= read -r f; do
  [[ -n "\$f" ]] || continue
  rm -f "\$f" 2>/dev/null && pruned=\$(( pruned + 1 ))
done < <(ls -1t "\$ARCH_DIR"/ppp-*.log.gz 2>/dev/null | tail -n +\$(( KEEP + 1 )))
(( pruned > 0 )) && LOG "已清理 \${pruned} 份旧归档，保留最近 \${KEEP} 份。"
LOG "ppp.log 轮转完成。"
EOF
  chmod +x /usr/local/bin/openppp2-logrotate.sh
}

setup_systemd_weekly_update() {
  if ! has_systemd; then
    warn "无 systemd，跳过自动更新/开机启动配置。"
    return 0
  fi
  detect_compose >/dev/null 2>&1 || true

  _write_stack_helper
  _write_update_script
  _write_logrotate_script

  cat >/etc/systemd/system/openppp2-update.service <<EOF
[Unit]
Description=openppp2 auto update (with health-gated rollback)
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-update.sh
EOF

  cat >/etc/systemd/system/openppp2-update.timer <<EOF
[Unit]
Description=Run openppp2 auto update weekly

[Timer]
OnCalendar=${DEFAULT_ONCAL}
Persistent=true
# 在计划时间点上随机抖动，避免大量机器同一秒一起拉镜像/重建（惊群、上游限流）。
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

  # 服务端 ppp.log 自动轮转（service + timer）
  cat >/etc/systemd/system/openppp2-logrotate.service <<EOF
[Unit]
Description=openppp2 server ppp.log rotation (archive + recreate)
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-logrotate.sh
EOF

  cat >/etc/systemd/system/openppp2-logrotate.timer <<EOF
[Unit]
Description=Run openppp2 ppp.log rotation check

[Timer]
OnCalendar=${PPP_LOG_ROTATE_ONCAL}
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
EOF

  # 开机延迟启动（可选）
  if [[ "${DEFAULT_BOOT_DELAY}" -gt 0 ]]; then
    _write_boot_service
  fi

  systemctl daemon-reload
  systemctl enable --now openppp2-update.timer >/dev/null 2>&1 || true
  systemctl enable --now openppp2-logrotate.timer >/dev/null 2>&1 || true
  if [[ "${DEFAULT_BOOT_DELAY}" -gt 0 ]]; then
    systemctl enable openppp2-boot.service >/dev/null 2>&1 || true
  fi

  info "已配置每周自动更新（${DEFAULT_ONCAL}），失败自动回滚：${AUTO_ROLLBACK}"
  info "已配置服务端 ppp.log 自动轮转（检查频率 ${PPP_LOG_ROTATE_ONCAL}，超过 ${PPP_LOG_MAX_MB}MB 归档+重建，保留 ${PPP_LOG_KEEP} 份）"
}

#!/usr/bin/env bash
# systemd.sh - systemd 集成：每周自动更新（digest 受控更新 + 健康门控回滚 + 旧镜像清理
#              + 失败通知 + 可选脚本自更新）+ 服务端 ppp.log 轮转 + 开机延迟启动

# 生成一个独立可执行的 stack 助手（boot/update/logrotate 复用，避免依赖 lib）
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

# 失败通知助手（systemd OnFailure 触发）。NOTIFY_WEBHOOK / NOTIFY_EMAIL 在生成时烘焙进脚本。
# 二者都为空时仅写 journald（保证失败一定可见，不再静默）。
_write_notify_script() {
  cat >/usr/local/bin/openppp2-notify.sh <<EOF
#!/usr/bin/env bash
# openppp2 维护失败通知（被 openppp2-notify@.service 调用，参数 \$1 = 失败的单元名）
set -uo pipefail
UNIT="\${1:-openppp2}"
HOST="\$(hostname 2>/dev/null || echo unknown)"
WEBHOOK="${NOTIFY_WEBHOOK}"
EMAIL="${NOTIFY_EMAIL}"
MSG="[openppp2] 维护任务失败：\${UNIT} @ \${HOST}（\$(date '+%F %T')）。排查：journalctl -u \${UNIT} -n 100 --no-pager"

# 1) journald / stderr（始终）
echo "\$MSG" >&2
command -v logger >/dev/null 2>&1 && logger -t openppp2 -p daemon.err "\$MSG" || true

# 2) webhook（可选，发送通用 {"text":...} JSON；飞书/企业微信等如需特定格式请自行改造本段）
if [[ -n "\$WEBHOOK" ]] && command -v curl >/dev/null 2>&1; then
  payload="\$(printf '{"text":"%s"}' "\$MSG")"
  curl -fsS -m 15 -H 'Content-Type: application/json' -d "\$payload" "\$WEBHOOK" >/dev/null 2>&1 || true
fi

# 3) 邮件（可选，需宿主机已配置可用的 mail 命令）
if [[ -n "\$EMAIL" ]] && command -v mail >/dev/null 2>&1; then
  printf '%s\n' "\$MSG" | mail -s "openppp2 维护失败：\${UNIT} @ \${HOST}" "\$EMAIL" >/dev/null 2>&1 || true
fi
exit 0
EOF
  chmod +x /usr/local/bin/openppp2-notify.sh
}

# 脚本自更新助手（可选，SELF_UPDATE=yes 时由更新任务调用）。
# 仅在本仓库出现"更高的 release tag"时，下载该 tag 的 tarball 并刷新 systemd 助手脚本/单元，
# 不触碰配置与容器。⚠ 会让 root 自动执行公网下载的新脚本，开启前请自行评估供应链风险。
_write_self_update_script() {
  cat >/usr/local/bin/openppp2-self-update.sh <<EOF
#!/usr/bin/env bash
set -uo pipefail
APP_DIR="${APP_DIR}"
SELF_REPO="${SELF_REPO}"
CUR_VER="${SCRIPT_VERSION}"
LOG() { echo "[\$(date '+%F %T')] [self-update] \$*"; }

command -v curl >/dev/null 2>&1 || { LOG "无 curl，跳过"; exit 0; }
command -v tar >/dev/null 2>&1 || { LOG "无 tar，跳过"; exit 0; }

latest="\$(curl -fsSL "https://api.github.com/repos/\${SELF_REPO}/releases?per_page=20" 2>/dev/null |
  grep -oE '"tag_name": *"v[0-9]+\.[0-9]+\.[0-9]+"' |
  head -n1 |
  sed -E 's/.*"(v[0-9]+\.[0-9]+\.[0-9]+)"/\1/')"
if [[ ! "\$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+\$ ]]; then
  LOG "未解析到合法的正式 release tag（得到 '\${latest:-空}'），跳过。"
  exit 0
fi

cur="v\${CUR_VER}"
newest="\$(printf '%s\n%s\n' "\$cur" "\$latest" | sort -V | tail -n1)"
if [[ "\$latest" == "\$cur" || "\$newest" != "\$latest" ]]; then
  LOG "当前 \$cur 已是最新或更新（最新 release：\$latest），无需自更新。"
  exit 0
fi

LOG "发现新版本 \$latest（当前 \$cur），下载并刷新 systemd 助手..."
tmp="\$(mktemp -d)"; trap 'rm -rf "\$tmp"' EXIT
url="https://github.com/\${SELF_REPO}/archive/refs/tags/\${latest}.tar.gz"
curl -fsSL "\$url" -o "\$tmp/repo.tgz" || { LOG "下载失败：\$url"; exit 1; }
tar -xzf "\$tmp/repo.tgz" -C "\$tmp" || { LOG "解压失败"; exit 1; }
dir="\$(find "\$tmp" -maxdepth 1 -mindepth 1 -type d -name 'openppp2-docker*' | head -n1)"
if [[ -z "\$dir" || ! -f "\$dir/install_openppp2.sh" || ! -f "\$dir/lib/systemd.sh" ]]; then
  LOG "项目结构异常，放弃自更新。"
  exit 1
fi
# 仅刷新 systemd 助手脚本/单元（不动配置/容器）。新代码会读取 \${APP_DIR}/.env 保留既有选项。
if OPENPPP2_BOOTSTRAPPED=1 bash "\$dir/install_openppp2.sh" --regen-systemd; then
  LOG "已刷新到 \$latest 的 systemd 助手。"
else
  LOG "刷新 systemd 助手失败。"
  exit 1
fi
EOF
  chmod +x /usr/local/bin/openppp2-self-update.sh
}

# 生成带回滚的更新脚本（基于不可变 digest 的受控更新）
_write_update_script() {
  local rollback="$AUTO_ROLLBACK"
  cat >/usr/local/bin/openppp2-update.sh <<EOF
#!/usr/bin/env bash
# openppp2 自动更新：
#   - 通过 .image_channel 记录的浮动标签"发现"上游新镜像，但运行时始终固定到不可变 digest；
#   - 切换到新 digest 后做健康检查，失败则回滚到旧 digest 并恢复配置；
#   - 更新成功后按 IMAGE_KEEP 清理旧镜像（保留上一个供回滚）。
set -uo pipefail
umask 077   # 备份快照含密钥配置，禁止世界可读
APP_DIR="${APP_DIR}"
COMPOSE_FILE="${COMPOSE_FILE}"
BACKUP_DIR="${BACKUP_DIR}"
AUTO_ROLLBACK="${rollback}"
IMAGE_KEEP="${IMAGE_KEEP}"
CHANNEL_DEFAULT="${DEFAULT_IMAGE}"
SELF_UPDATE="${SELF_UPDATE}"
SELF_UPDATE_SH="/usr/local/bin/openppp2-self-update.sh"
STACK=/usr/local/bin/openppp2-stack.sh
LOG() { echo "[\$(date '+%F %T')] \$*"; }

# 串行化：与 logrotate/boot 共用一把锁，避免并发对同一 compose 栈做 pull/recreate 打架。
LOCK="/run/openppp2.lock"
exec 9>"\$LOCK" 2>/dev/null || exec 9>/tmp/openppp2.lock
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { LOG "另一个 openppp2 维护任务正在运行，跳过本次更新。"; exit 0; }
fi

# 可选：先做脚本自更新（仅刷新 systemd 助手；本次仍用当前脚本继续镜像更新）
if [[ "\$SELF_UPDATE" == "yes" && -x "\$SELF_UPDATE_SH" ]]; then
  LOG "脚本自更新已开启，检查仓库新版本..."
  "\$SELF_UPDATE_SH" || LOG "脚本自更新未完成（忽略，继续镜像更新）。"
fi

cd "\$APP_DIR" || exit 1
[[ -f "\$COMPOSE_FILE" ]] || { LOG "无 compose 文件，跳过"; exit 0; }

# 解析镜像 ref 的不可变 digest（repo@sha256:...）
resolve_digest() {
  docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "\$1" 2>/dev/null |
    grep -m1 '@sha256:' || true
}

# 发现通道（浮动标签）：优先 .image_channel；否则用 .image 去掉 @digest；再不行用默认
CHANNEL="\$(cat "\$APP_DIR/.image_channel" 2>/dev/null || true)"
if [[ -z "\$CHANNEL" ]]; then
  _cur_img="\$(cat "\$APP_DIR/.image" 2>/dev/null || true)"
  CHANNEL="\${_cur_img%@*}"
fi
[[ -n "\$CHANNEL" ]] || CHANNEL="\$CHANNEL_DEFAULT"

# 当前 compose 用的镜像引用（可能已是 digest）
CUR_REF="\$(grep -m1 -E '^[[:space:]]*image:' "\$COMPOSE_FILE" | sed -E 's/^[[:space:]]*image:[[:space:]]*//')"

# 当前在跑的 openppp2 容器（用于回滚 retag 与健康检查）
mapfile -t CONTS < <(docker ps -a --filter name=openppp2 --format '{{.Names}}')

# 快照旧镜像 ID/ref（回滚兜底用）
declare -A OLD_IMG_ID OLD_IMG_REF
for c in "\${CONTS[@]}"; do
  OLD_IMG_REF["\$c"]="\$(docker inspect -f '{{.Config.Image}}' "\$c" 2>/dev/null)"
  OLD_IMG_ID["\$c"]="\$(docker inspect -f '{{.Image}}' "\$c" 2>/dev/null)"
done

# 备份配置（回滚用）
TS="\$(date +%Y%m%d_%H%M%S)"
SNAP="\${BACKUP_DIR}/auto-\${TS}"
mkdir -p "\$SNAP"
cp -a "\$APP_DIR"/appsettings*.json "\$SNAP"/ 2>/dev/null || true
cp -a "\$COMPOSE_FILE" "\$SNAP"/ 2>/dev/null || true
cp -a "\$APP_DIR"/seccomp-openppp2.json "\$SNAP"/ 2>/dev/null || true

# 1) 拉取发现通道镜像并解析其 digest
LOG "拉取发现通道镜像：\$CHANNEL"
if ! docker pull "\$CHANNEL" >/dev/null 2>&1; then
  LOG "pull 失败（\$CHANNEL），保持现状退出。"
  exit 0
fi
NEW_REF="\$(resolve_digest "\$CHANNEL")"
if [[ -z "\$NEW_REF" ]]; then
  LOG "无法解析 \$CHANNEL 的 digest，跳过本次更新（避免漂移到不可复现的标签）。"
  exit 0
fi

# 2) 与当前固定 digest 比对
if [[ "\$NEW_REF" == "\$CUR_REF" ]]; then
  LOG "已是最新（\$NEW_REF），无需更新。"
  exit 0
fi

LOG "发现新镜像：\${CUR_REF:-未知} -> \$NEW_REF，切换并重建容器..."
# 把 compose 与 .image 切到新 digest（所有 service 的 image 行）
sed -i -E "s|^([[:space:]]*image:[[:space:]]*).*|\\1\$NEW_REF|" "\$COMPOSE_FILE"
echo "\$NEW_REF" >"\$APP_DIR/.image"
"\$STACK" up -d --remove-orphans

# 3) 健康检查：容器 Running + ppp 进程 + HEALTHCHECK + 真实出网/监听探测
health_ok() {
  local ok=1 c st bind hport sport hs
  local egress_url="https://ifconfig.me"
  local -a sauth=()
  for c in "\${CONTS[@]}"; do
    st="\$(docker inspect -f '{{.State.Status}}' "\$c" 2>/dev/null || echo missing)"
    if [[ "\$st" != "running" ]]; then LOG "不健康：\$c 状态=\$st（非 running）"; ok=0; continue; fi
    hs="\$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "\$c" 2>/dev/null || true)"
    if [[ -n "\$hs" && "\$hs" != "healthy" ]]; then LOG "不健康：\$c HEALTHCHECK=\$hs"; ok=0; continue; fi
    if ! docker exec "\$c" sh -c 'pgrep -x ppp >/dev/null 2>&1 || pidof ppp >/dev/null 2>&1'; then
      LOG "不健康：\$c 内无 ppp 进程"; ok=0; continue
    fi
  done

  if [[ -f "\$APP_DIR/.instances" ]] && command -v curl >/dev/null 2>&1; then
    local svc cfg tun tunip tungw nic ngw suser spass
    while IFS='|' read -r svc cfg tun tunip tungw nic ngw hport sport _mux; do
      [[ -z "\$svc" ]] && continue
      bind=""
      suser=""
      spass=""
      if command -v jq >/dev/null 2>&1 && [[ -f "\$APP_DIR/\$cfg" ]]; then
        bind="\$(jq -r '.client["http-proxy"].bind // ""' "\$APP_DIR/\$cfg" 2>/dev/null)"
        suser="\$(jq -r '.client["socks-proxy"].username // ""' "\$APP_DIR/\$cfg" 2>/dev/null)"
        spass="\$(jq -r '.client["socks-proxy"].password // ""' "\$APP_DIR/\$cfg" 2>/dev/null)"
      fi
      [[ -n "\$bind" ]] || continue
      if [[ -n "\$hport" && "\$hport" != "0" ]]; then
        curl -fsS -x "http://\${bind}:\${hport}" --max-time 10 -o /dev/null "\$egress_url" 2>/dev/null \\
          || { LOG "不健康：\$svc HTTP 代理出网失败 (\${bind}:\${hport})"; ok=0; }
      fi
      if [[ -n "\$sport" && "\$sport" != "0" ]]; then
        # 配置了 SOCKS5 用户名/密码则带认证探测，避免 openppp2 要求认证时 407 误判不健康进而误回滚
        sauth=()
        [[ -n "\$suser" ]] && sauth=(--proxy-user "\${suser}:\${spass}")
        curl -fsS "\${sauth[@]}" -x "socks5h://\${bind}:\${sport}" --max-time 10 -o /dev/null "\$egress_url" 2>/dev/null \\
          || { LOG "不健康：\$svc SOCKS5 代理出网失败 (\${bind}:\${sport})"; ok=0; }
      fi
    done <"\$APP_DIR/.instances"
  fi

  if [[ -f "\$APP_DIR/.role" && "\$(cat "\$APP_DIR/.role" 2>/dev/null)" == "server" ]]; then
    local sport_srv
    sport_srv="\$(jq -r '.tcp.listen.port // 20000' "\$APP_DIR"/appsettings.json 2>/dev/null || echo 20000)"
    for c in "\${CONTS[@]}"; do
      docker exec "\$c" sh -c "ss -ltn 2>/dev/null | grep -q ':\${sport_srv}'" \\
        || { LOG "不健康：\$c 未在 \${sport_srv} 监听 TCP"; ok=0; }
      docker exec "\$c" sh -c "ss -lun 2>/dev/null | grep -q ':\${sport_srv}'" \\
        || { LOG "不健康：\$c 未在 \${sport_srv} 监听 UDP"; ok=0; }
    done
  fi

  return \$((ok == 1 ? 0 : 1))
}

# 更新成功后按 IMAGE_KEEP 清理旧镜像（按创建时间倒序，保留最新 N 个，其余 rmi；在用/被引用的会失败，忽略）
prune_images() {
  local keep="\$IMAGE_KEEP" repo ids n=0
  [[ "\$keep" =~ ^[0-9]+\$ ]] || return 0
  [[ "\$keep" -ge 1 ]] || return 0
  repo="\${CHANNEL%@*}"; repo="\${repo%:*}"
  ids="\$(docker images "\$repo" --format '{{.ID}}\t{{.CreatedAt}}' 2>/dev/null |
    sort -k2 -r | awk '!seen[\$1]++ {print \$1}' | tail -n +\$((keep + 1)))"
  [[ -n "\$ids" ]] || return 0
  while IFS= read -r id; do
    [[ -n "\$id" ]] || continue
    docker rmi "\$id" >/dev/null 2>&1 && n=\$((n + 1)) || true
  done <<<"\$ids"
  (( n > 0 )) && LOG "已清理 \$n 个旧镜像，保留最新 \${keep} 个。"
  return 0
}

LOG "等待服务就绪并做健康检查（最多重试 6 次）..."
HC_OK=0
for _i in 1 2 3 4 5 6; do
  sleep 10
  if health_ok; then HC_OK=1; break; fi
  LOG "第 \${_i} 次健康检查未通过，继续等待..."
done
if [[ "\$HC_OK" == "1" ]]; then
  LOG "更新成功，健康检查通过（运行镜像：\$NEW_REF）。"
  prune_images
  exit 0
fi

# 4) 失败回滚
if [[ "\$AUTO_ROLLBACK" != "yes" ]]; then
  LOG "健康检查未通过，且未开启自动回滚（AUTO_ROLLBACK=\$AUTO_ROLLBACK）。请手动检查。"
  exit 1
fi

LOG "健康检查未通过，回滚到旧镜像并恢复配置（旧 digest：\${CUR_REF:-未知}）..."
# 旧镜像本地仍在（未清理），把 compose/.image 指回旧 digest 即可；retag 作为兜底
for c in "\${CONTS[@]}"; do
  if [[ -n "\${OLD_IMG_ID[\$c]:-}" && -n "\${OLD_IMG_REF[\$c]:-}" ]]; then
    docker tag "\${OLD_IMG_ID[\$c]}" "\${OLD_IMG_REF[\$c]}" 2>/dev/null || true
  fi
done
if [[ -n "\$CUR_REF" ]]; then
  sed -i -E "s|^([[:space:]]*image:[[:space:]]*).*|\\1\$CUR_REF|" "\$COMPOSE_FILE"
  echo "\$CUR_REF" >"\$APP_DIR/.image"
fi
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
  _write_notify_script
  _write_self_update_script
  _write_update_script
  _write_logrotate_script

  # 失败通知模板单元（%i = 失败的单元名，由 OnFailure 传入）
  cat >/etc/systemd/system/openppp2-notify@.service <<EOF
[Unit]
Description=openppp2 maintenance failure notifier for %i

[Service]
Type=oneshot
ExecStart=/usr/local/bin/openppp2-notify.sh %i
EOF

  cat >/etc/systemd/system/openppp2-update.service <<EOF
[Unit]
Description=openppp2 auto update (digest-pinned, health-gated rollback)
After=docker.service network-online.target
Wants=docker.service network-online.target
OnFailure=openppp2-notify@%n.service

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
# 在计划时间点上随机抖动，避免大量机器同一秒一起拉镜像/重建（惊群、上游限流），即天然的灰度铺开。
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
OnFailure=openppp2-notify@%n.service

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

  info "已配置每周自动更新（${DEFAULT_ONCAL}，digest 固定 + 失败回滚：${AUTO_ROLLBACK}，失败通知：journald$([[ -n "$NOTIFY_WEBHOOK" ]] && echo +webhook)$([[ -n "$NOTIFY_EMAIL" ]] && echo +email)，脚本自更新：${SELF_UPDATE}）"
  info "已配置服务端 ppp.log 自动轮转（检查频率 ${PPP_LOG_ROTATE_ONCAL}，超过 ${PPP_LOG_MAX_MB}MB 归档+重建，保留 ${PPP_LOG_KEEP} 份）"
}

# openppp2-docker

> **v2.3 防卡死版** — 全面修复 v2.2 在某些环境下一键脚本会卡住的问题：所有网络、apt、docker、systemd 操作都加了硬超时；非交互模式自动跳过 prompt；镜像拉取失败自动回退到本地 Dockerfile 构建。

一键安装 / 更新 openppp2 的 Docker 化部署脚本。Server / Client 双模式、多实例、自动更新 + 健康检查 + 失败回滚。

---

## v2.3 关键改动（针对"脚本卡住"问题）

| 问题 | 根因 | v2.3 修复 |
| --- | --- | --- |
| `apt-get update` 卡死 | 上游源慢 / IPv6 黑洞 / dpkg lock 被 unattended-upgrades 占用 | 硬超时 `APT_TIMEOUT=180s`，等 dpkg lock 最多 60s 后强行继续，强制 IPv4 |
| `docker pull` 卡死 | GHCR 镜像不存在 / 网络慢 | 硬超时 `COMPOSE_PULL_TIMEOUT=600s`，**失败自动回退到本地 Dockerfile 构建** |
| `compose up -d` 卡死 | 镜像拉取卡死 / 容器启动失败 | 硬超时 `COMPOSE_UP_TIMEOUT=180s`，失败打印最近 30 行日志 |
| 健康检查 60s 阻塞 | v2.2 写死 sleep 60 | 改为带进度条的 `HEALTH_CHECK_TIMEOUT=40s` 轮询 |
| `read` 永远等待 | 脚本通过 `curl \| bash` 运行，stdin 没接终端 | **自动检测 NONINTERACTIVE**，无 TTY 时所有 prompt 用默认值；交互模式 prompt 加 5 分钟超时 |
| `systemctl enable --now` 卡死 | systemd 单元依赖循环 / sd-bus 慢 | 所有 systemctl 调用 `timeout 30s` 包住 |
| `curl` 公网 IP 检测卡死 | 被墙 / 慢 | `curl_retry` 显式 `--connect-timeout 10 --max-time 60` |
| 公网 IP 检测失败 → 整个脚本中止 | 之前直接 die | 检测失败时仅 warn 并要求手动输入 |

### 调试新工具

```bash
# 完整 trace（每条命令打印行号和时间）
sudo OPENPPP2_DEBUG=1 ./install_openppp2.sh

# 完全无人值守（CI / 批量部署）
sudo OPENPPP2_NONINTERACTIVE=1 \
     SERVER_IP=1.2.3.4 SERVER_PORT=20000 \
     CLIENT_NIC=ens192 \
     ./install_openppp2.sh

# 增加单步超时（网络很慢的环境）
sudo NET_TIMEOUT=120 COMPOSE_PULL_TIMEOUT=1200 ./install_openppp2.sh

# 禁用本地 build fallback（生产环境只想用预构建镜像）
sudo ALLOW_LOCAL_BUILD=no ./install_openppp2.sh
```

---

## 完整特性

- 🚀 **一键安装**：自动检测并安装 Docker、Compose 及所有系统依赖
- 🔀 **双模式**：Server / Client 引导式交互配置
- 📦 **多实例**：同机多个客户端容器，各自独立 TUN / 端口 / 配置
- 🔄 **自动更新 + 回滚**：systemd timer 周更新，健康检查不通过自动回退到旧镜像，可发送 webhook 通知
- 🛡️ **多层容器加固**：
  - 自定义 seccomp profile（仅放开 io_uring 必要 syscall）
  - `cap_drop ALL` + 白名单 `NET_ADMIN / NET_RAW / NET_BIND_SERVICE`
  - `no-new-privileges:true` 禁运行期提权
  - 非 root 用户 `ppp(uid=1000)` 启动 + tini PID 1
- 📦 **镜像下载校验**：CI 计算上游 zip 的 SHA256 通过 build-arg 注入 Dockerfile
- 📊 **资源与日志限制**：内存上限 / CPU 上限 / 日志大小都写进 compose
- 🌐 **网络自适应**：自动探测网卡、IP、网关（纯本地命令，绝不卡）

---

## 前置条件

- **OS**：Debian / Ubuntu（推荐 11+）
- **内核**：Linux 5.1+（io_uring 必需）
- **权限**：root 或 sudo
- **TUN**（Client 模式）：`/dev/net/tun` 可用，`modprobe tun`
- **网络**：Client 能访问 Server 的 PPP 端口（默认 UDP+TCP 20000）

---

## 目录结构

```
openppp2-docker/
├── install_openppp2.sh        # 主入口
├── config.sh                  # 全局常量 + 超时 + 防卡死开关
├── appsettings.base.json      # 基准配置模板
├── Dockerfile                 # 多阶段 + SHA256 校验 + 非 root + HEALTHCHECK
├── .github/workflows/build.yml
└── lib/
    ├── core.sh                # 工具 + prompt(带超时) + curl_retry + apt_install
    ├── network.sh             # detect_net + random_free_port + IP 转发
    ├── seccomp.sh             # seccomp profile 生成
    ├── docker.sh              # daemon 安装 + compose 探测 + 健康检查 + 本地 build fallback
    ├── compose.sh             # YAML 生成（cap_drop / 资源 / 日志 / init / 非 root）
    ├── systemd.sh             # boot-delay + weekly update timer + 健康检查回滚
    ├── client.sh              # 多实例 add / list / delete
    └── backup.sh              # 备份 + 恢复
```

---

## 快速开始

### 服务端

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh \
  -o install_openppp2.sh
chmod +x install_openppp2.sh
sudo ./install_openppp2.sh
# 选择 1 - 服务端
# 输入公网 IP / 监听 IP
```

> **重要**：通过 `curl | sudo bash` 这种管道形式运行会触发非交互模式（因为 stdin 不是 TTY），所有 prompt 会使用默认值。如果你需要交互，请先 `curl -o` 下载文件再运行。

### 客户端

```bash
sudo ./install_openppp2.sh
# 选择 2 - 客户端
# 输入服务端 IP / 端口
```

### 完全无人值守（CI / 批量部署）

```bash
sudo OPENPPP2_NONINTERACTIVE=1 \
     ROLE=2 \
     SERVER_IP=1.2.3.4 SERVER_PORT=20000 \
     IMAGE=ghcr.io/lucifer988/openppp2:latest \
     APP_CFG_NAME=appsettings.json \
     MAIN_SERVICE_NAME=openppp2 \
     CLIENT_NIC=ens192 \
     USE_MUX=no USE_PROXY=no \
     ACTION=1 \
     ./install_openppp2.sh
```

---

## 镜像版本管理

CI 每周构建会同时打两个 tag：

| Tag | 用途 | 推荐 |
| --- | --- | --- |
| `:latest`             | 跟随上游每周更新 | 个人使用，开了 weekly timer |
| `:<upstream-tag>`     | 例如 `:1.0.0.26016` | 生产环境，可重现部署 |

固定版本：

```bash
sudo OPENPPP2_IMAGE_TAG=1.0.0.26016 ./install_openppp2.sh
```

---

## 故障排查

### 脚本"卡住"了，怎么办？

**v2.3 应该不会再卡，但如果还是遇到**：

1. 先用 `OPENPPP2_DEBUG=1` 重跑，看停在哪一行
   ```bash
   sudo OPENPPP2_DEBUG=1 ./install_openppp2.sh 2>&1 | tee /tmp/install.log
   ```
2. 看 `[*]` 日志最后一条是什么阶段
3. 常见停顿点：
   - `等待其他 apt 进程释放锁...` → `sudo systemctl stop unattended-upgrades` 后重试
   - `拉取镜像（最多 600s）...` → 网络问题，可设置 `OPENPPP2_IMAGE_REPO` 用国内镜像源
   - `健康检查容器...` → 看 `docker logs openppp2` 找原因

### apt-get 卡在 IPv6

v2.3 已自动写 `/etc/apt/apt.conf.d/99force-ipv4`，强制走 IPv4。

### Docker pull 卡死 / GHCR 镜像不存在

v2.3 会自动回退到本地构建（`ALLOW_LOCAL_BUILD=yes` 默认）。如果你的服务器无法访问 GitHub，可以本地预先 build：

```bash
cd openppp2-docker
docker build -t ghcr.io/lucifer988/openppp2:latest .
sudo ./install_openppp2.sh
```

### 健康检查未通过

```bash
docker logs openppp2 --tail 100
docker inspect --format '{{json .State.Health}}' openppp2 | jq
```

常见原因：
- `io_uring_queue_init: Operation not permitted` → seccomp profile 缺失，重新跑安装脚本会自动生成
- TUN 设备没权限 → 确认 `/dev/net/tun` 存在且 compose 里有 `devices: - /dev/net/tun:/dev/net/tun`
- 内核 < 5.1 → 升级内核

### 容器无法启动

```bash
docker compose -f /opt/openppp2/docker-compose.yml logs --tail=200
cat /opt/openppp2/appsettings.json | jq .
```

### 客户端连不到服务端

```bash
nc -zv  <服务端IP> 20000   # TCP
nc -zuv <服务端IP> 20000   # UDP
sudo ss -tulnp | grep 20000   # 服务端检查
sudo ufw status               # 防火墙
```

### 端口冲突

脚本会自动从 10000-60000 随机分配，仍有冲突可手动改 `appsettings.json` 的 `http-proxy.port` / `socks-proxy.port` 后重启容器。

### 卸载 / 重装

```bash
sudo ./install_openppp2.sh   # 选 2 卸载
sudo ./install_openppp2.sh   # 重新选 1 安装
```

---

## 环境变量速查（v2.3）

```bash
# === 超时（全部秒）===
NET_TIMEOUT=60               # curl 单次请求
NET_CONNECT_TIMEOUT=10       # curl TCP 握手
APT_TIMEOUT=180              # apt-get update / install
DOCKER_PULL_TIMEOUT=300      # 单镜像 docker pull
COMPOSE_PULL_TIMEOUT=600     # docker compose pull
COMPOSE_UP_TIMEOUT=180       # docker compose up -d
HEALTH_CHECK_TIMEOUT=40      # 容器健康检查总等待
HEALTH_GRACE_SEC=20          # 容器启动后等多久才检查

# === 行为开关 ===
OPENPPP2_NONINTERACTIVE=1    # 强制非交互（默认按 stdin TTY 自动判断）
ALLOW_LOCAL_BUILD=yes        # 镜像拉取失败时回退到本地 Dockerfile 构建
OPENPPP2_DEBUG=1             # 开 set -x

# === 镜像 ===
OPENPPP2_IMAGE_REPO=ghcr.io/lucifer988/openppp2
OPENPPP2_IMAGE_TAG=latest

# === 资源限制 ===
OPENPPP2_MEM_LIMIT=512M
OPENPPP2_MEM_RESERVE=64M
OPENPPP2_CPU_LIMIT=1.0

# === 部署相关 ===
CLIENT_NIC=ens192            # 客户端网卡
OPENPPP2_BOOT_DELAY=20       # 开机延迟启动（秒，0=禁用）
STRICT_BOOT_DELAY_MODE=no    # yes=systemd 全权控制启动顺序
```

---

## 自动更新与失败回滚

`openppp2-update.timer` 每周日 03:00 UTC（默认）触发，工作流：

1. 记录所有服务**当前**镜像 digest
2. `docker compose pull`（600s 超时）
3. 镜像无变化 → 直接退出
4. `docker compose up -d`（180s 超时）
5. 等 30s 让容器进入稳态
6. 逐个跑健康检查
7. 任一不健康 → 用旧 digest 重新 tag 当前镜像引用并重启 = 回滚

可选通知：在 `/etc/default/openppp2-update` 写入

```bash
OPENPPP2_UPDATE_WEBHOOK="https://api.day.app/<KEY>/{title}/{body}"
```

退出码：`0=成功 / 1=失败已回滚 / 2=回滚也失败`

更新日志：`/var/log/openppp2-update.log`

---

## 多实例

每个新增 client 自动分配：

- TUN 设备：`ppp2`, `ppp3` ...
- TUN IP 段：`10.0.2.0/30`, `10.0.3.0/30` ...
- HTTP / SOCKS5 端口：10000-60000 随机
- 配置文件：`appsettings-<svc>.json`
- IP 路由表 / DNS 规则：`ip-<svc>.txt`, `dns-rules-<svc>.txt`

---

## 安全建议

生产部署必做：

1. 修改 `appsettings.json` 里的所有密钥（用 `openssl rand -base64 24` 生成）
2. `iptables` / `ufw` 把 20000 端口限制在已知客户端 IP 段
3. 设置 `OPENPPP2_UPDATE_WEBHOOK`，更新失败第一时间知道
4. 用 `:1.0.0.X` 固定 tag 而不是 `:latest`

---

## 更新日志

### v2.3.0 (2026-05) — 防卡死专版

- 🔧 **所有阻塞操作加硬超时**：apt / curl / docker pull / compose up / systemctl 都不会无限等待
- 🔧 **非交互模式自动检测**：`! -t 0` 时所有 prompt 用默认值，不再阻塞
- 🔧 **prompt 5 分钟超时**：交互模式下也不会永远等
- 🔧 **镜像拉取失败 → 本地构建**：`ALLOW_LOCAL_BUILD=yes` 默认开启
- 🔧 **健康检查改为进度反馈**：v2.2 阻塞 60s 改为 40s 轮询带进度
- 🔧 **dpkg lock 智能等待**：最多 60s 后强行继续
- 🔧 **OPENPPP2_DEBUG 调试模式**：一行 export 全程 trace
- 🔧 **网络探测纯本地命令**：detect_net 不再发任何网络请求

### v2.2.0

- 🔐 SHA256 镜像下载校验、非 root 用户、tini、HEALTHCHECK
- 🛡️ cap_drop ALL、no-new-privileges、资源限制、日志轮转
- 🔁 自动更新带健康检查 + 失败回滚 + webhook 通知
- 🎯 镜像版本管理拆分 REPO + TAG

### v2.1.0

- ✅ ShellCheck 警告全部修复
- 📦 Dockerfile 多阶段构建

### v2.0

- 🔨 模块化重构

---

## 许可

MIT。openppp2 本体许可遵循 [liulilittle/openppp2](https://github.com/liulilittle/openppp2)。

# openppp2-docker

> **v2.2 增强版** — 镜像 SHA256 校验、容器最小化能力 + 非 root 运行、内置 HEALTHCHECK、资源与日志限制、自动更新带健康检查与失败回滚、镜像版本可固定可滚动。

一键安装/更新 openppp2 的 Docker 化部署脚本。支持 Server / Client 双模式、同机多实例、自动更新与配置回滚。

Deploy openppp2 in Docker with one command. Supports server/client modes, multiple client instances, auto-updates with health-checked rollback, and config rollback.

---

## 特性

- 🚀 **一键安装**：自动检测并安装 Docker、Compose 及所有系统依赖
- 🔀 **双模式**：Server / Client，脚本引导式交互配置
- 📦 **多实例**：同机运行多个客户端容器，各自独立的 TUN 设备和配置
- 🔄 **自动更新 + 回滚**：systemd timer 每周拉取最新镜像、跑健康检查；不健康则自动回退到旧 digest 并可发送 webhook 通知
- 🛡️ **失败回滚（配置）**：配置文件自动备份，出问题一键恢复
- 🔒 **多层容器加固**：
  - 自定义 seccomp profile（仅放开 io_uring 必要系统调用）
  - `cap_drop: ALL` 之后只白名单 `NET_ADMIN / NET_RAW / NET_BIND_SERVICE`
  - `no-new-privileges:true` 禁止运行期提权
  - 镜像以非 root 用户 `ppp(uid=1000)` 启动，由 tini 接管 PID 1
- 📦 **镜像下载校验**：CI 计算上游 zip 的 SHA256 并通过 build-arg 注入 Dockerfile 校验
- 📊 **资源与日志限制**：内存上限 / CPU 上限 / 日志大小都写进 compose
- 🌐 **网络自适应**：自动探测网卡、IP、网关，支持 Docker 代理加速镜像拉取
- ✅ **代码质量**：通过 ShellCheck 静态分析，遵循 Shell 最佳实践

---

## 架构兼容矩阵

| 架构              | 镜像构建 | 客户端 TUN  | 服务端       | 备注 |
| ----------------- | -------- | ----------- | ------------ | --- |
| `linux/amd64`     | ✅ CI 每周构建 simd 变体 | ✅ | ✅ | 主线，最稳。需要 CPU 支持 SSE4 |
| `linux/arm64`     | ⚠️ 暂未构建（上游 zip 名 `aarch64`，可扩展 CI） | 理论可行 | 理论可行 | 树莓派/Graviton 用户可本地 build |
| `linux/arm/v7`    | ⚠️ 暂未构建 | 理论可行 | 理论可行 | 同上 |
| 内核 `< 5.1`     | — | ❌ | ❌ | io_uring 至少需要 Linux 5.1+ |
| 宿主机无 `/dev/net/tun` | — | ❌ | ✅ | 服务端不依赖 TUN |

> CI 默认只构建 amd64-simd 变体。如要 arm64/armv7，可本地 build 并通过 `OPENPPP2_ZIP_URL` 指向对应上游 zip；同时建议传入 `OPENPPP2_ZIP_SHA256`。

---

## 前置条件

- **操作系统**：Debian / Ubuntu（推荐），其他 Linux 需手动安装 Docker
- **内核**：Linux 5.1+（io_uring 支持）
- **权限**：root 或 sudo
- **TUN 设备**（Client 模式）：宿主机需支持 `/dev/net/tun`
- **网络**：Client 能访问 Server 的 PPP 端口（默认 UDP+TCP 20000）

---

## 目录结构

```
openppp2-docker/
├── install_openppp2.sh          # 主入口 — 菜单路由 + 安装/卸载编排层
├── config.sh                     # 集中配置：路径、镜像、默认值、版本号
├── appsettings.base.json         # 基准配置模板（首次安装时据此生成实例配置）
├── Dockerfile                    # 多阶段构建 + SHA256 校验 + 非 root + HEALTHCHECK
├── .github/workflows/build.yml   # CI：每周拉上游 release、计算校验和、推 GHCR
└── lib/                          # 模块化函数库（按依赖顺序加载）
    ├── core.sh                   # 核心工具：日志、交互、依赖、curl_retry、safer_cd
    ├── network.sh                # 网络工具：端口检测、网卡/IP/网关探测、IP 转发
    ├── seccomp.sh                # seccomp 安全策略生成
    ├── docker.sh                 # Docker 管理：daemon 安装、Compose 检测、代理、健康检查
    ├── compose.sh                # Compose YAML 生成（含 cap_drop/资源限制/日志轮转）
    ├── systemd.sh                # systemd 集成：周更新（带健康检查+失败回滚）、开机延迟
    ├── client.sh                 # 客户端操作：新增实例、查看配置、删除实例、交互选择
    └── backup.sh                 # 备份与恢复
```

---

## Docker 一键安装

> 推荐：直接用下面这一条命令安装。脚本会自动安装/检测 Docker、Docker Compose、依赖工具，并拉取完整项目文件，不再需要手动下载 `config.sh` 或 `lib/` 目录。

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh | sudo bash
```

执行后按菜单选择：

```text
1) 安装 openppp2
```

然后继续选择部署角色：

```text
1) 服务端（Server）
2) 客户端（Client）
```

### 传统下载后运行

如果你不想用管道执行，也可以先下载再运行：

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o install_openppp2.sh
sudo bash install_openppp2.sh
```

> 新版 `install_openppp2.sh` 已支持单文件启动：即使当前目录没有 `config.sh`、`appsettings.base.json`、`lib/*.sh`，脚本也会自动从 GitHub main 分支拉取完整项目临时副本，然后继续安装。因此不会再出现 `/root/config.sh: No such file or directory`。

### 使用指定镜像版本安装

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o /tmp/install_openppp2.sh
sudo OPENPPP2_IMAGE_TAG=1.0.0.26016 bash /tmp/install_openppp2.sh
```

---

## 快速开始

### 服务端部署

```bash
# 一键启动安装菜单
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh | sudo bash

# 菜单中依次选择：
# 1) 安装 openppp2
# 1) 服务端（Server）
# 输入公网 IP: 1.2.3.4
# 输入监听 IP: 1.2.3.4（或内网 IP）

# 验证运行
docker compose -f /opt/openppp2/docker-compose.yml ps
docker compose -f /opt/openppp2/docker-compose.yml logs -f
```

### 客户端部署

```bash
# 一键启动安装菜单
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh | sudo bash

# 菜单中依次选择：
# 1) 安装 openppp2
# 2) 客户端（Client）
# 输入服务端 IP: 1.2.3.4
# 输入服务端端口: 20000

# 测试代理（端口由脚本自动分配，可在安装结束输出中查看）
curl -x http://127.0.0.1:<HTTP_PORT> https://ifconfig.me
curl -x socks5://127.0.0.1:<SOCKS_PORT> https://ifconfig.me
```

### 日常更新（手动）

```bash
cd /opt/openppp2
docker compose pull
docker compose up -d --remove-orphans
```

> 自动更新已交给 `openppp2-update.timer`，每周日运行一次（带回滚）。

---

## 交互菜单（7 项）

| # | 功能          | 说明                                          |
| --- | ----------- | ------------------------------------------- |
| 1 | 安装 openppp2 | 交互式配置 Server 或 Client                       |
| 2 | 卸载 openppp2 | 停止容器、清理 systemd、可选保留备份                      |
| 3 | 新增客户端实例     | 在同机追加额外的 client 容器                          |
| 4 | 查看客户端配置     | 列出所有 client 的 server/SOCKS5/HTTP 信息         |
| 5 | 删除客户端实例     | 选择并安全移除指定 client 及其配置                       |
| 6 | 备份当前配置      | 备份所有 appsettings\*.json、compose.yml、seccomp |
| 7 | 回滚          | 从最新备份恢复全部配置文件                               |

---

## 环境变量（无人值守 / 调参）

```bash
# === 安装阶段 ===
CLIENT_NIC=ens192                        # 指定客户端网卡
OPENPPP2_BOOT_DELAY=20                   # 开机延迟启动（秒，0=禁用）
STRICT_BOOT_DELAY_MODE=yes               # systemd 全权控制启动顺序

# === 镜像版本管理（v2.2 新）===
OPENPPP2_IMAGE_REPO=ghcr.io/lucifer988/openppp2
OPENPPP2_IMAGE_TAG=latest                # 改成 1.0.0.26016 即可固定版本

# === 资源限制（v2.2 新）===
OPENPPP2_MEM_LIMIT=512M                  # 容器内存上限
OPENPPP2_MEM_RESERVE=64M                 # 软预留
OPENPPP2_CPU_LIMIT=1.0                   # CPU 配额

# 例：固定到具体版本、跳到 1GB 内存
OPENPPP2_IMAGE_TAG=1.0.0.26016 OPENPPP2_MEM_LIMIT=1G sudo ./install_openppp2.sh
```

---

## 镜像版本管理（v2.2 新）

CI 每次构建会同时打两个 tag：

| Tag | 用途 | 推荐用户 |
| --- | --- | --- |
| `:latest`           | 跟随上游每周自动更新 | 想省心，开了 weekly timer，并对失败回滚有信心 |
| `:<upstream-tag>`   | 例如 `:1.0.0.26016`，永远指向那次构建的产物 | 生产环境，要求可重现部署、可显式升级 |

固定版本部署：

```bash
# 安装时用环境变量覆盖
OPENPPP2_IMAGE_TAG=1.0.0.26016 sudo ./install_openppp2.sh

# 或安装完成后修改 docker-compose.yml 的 image: 行，然后
cd /opt/openppp2 && docker compose up -d
```

---

## 自动更新与失败回滚（v2.2 新）

`openppp2-update.timer` 每周日凌晨 03:00 UTC（默认）触发 `openppp2-update.service`，
后者执行 `/usr/local/bin/openppp2-update.sh`，工作流：

1. 记录所有服务**当前容器使用的镜像 digest** 到 `/opt/openppp2/.last_image_digests`
2. `docker compose pull`
3. 比对 digest，没变化 → 直接退出
4. `docker compose up -d --remove-orphans`
5. 等 `HEALTH_GRACE_SEC`（默认 60 秒）让容器进入稳态
6. 逐个服务跑健康检查（看 `.State.Health.Status` + 排查 io_uring 拒绝）
7. 任一服务不健康 → 用步骤 1 记录的旧 digest 重新 `docker tag` 当前镜像引用，再 `up -d` 一次

可选通知：在 `/etc/default/openppp2-update` 写入

```bash
OPENPPP2_UPDATE_WEBHOOK="https://api.day.app/<KEY>/{title}/{body}"
```

`{title}` 会被替换为 `openppp2-success` / `openppp2-rolled-back` / `openppp2-FATAL`，
`{body}` 是简短说明，方便 Bark / Server 酱 / 企业微信 / 自建 webhook 接入。

更新日志统一写到 `/var/log/openppp2-update.log`。

---

## 多实例（Client）

每个新增实例自动分配独立的：

- TUN 设备名（`ppp2`, `ppp3` ...）
- TUN IP 段（`10.0.2.0/30`, `10.0.3.0/30` ...）
- HTTP / SOCKS5 代理端口（在 10000-60000 区间随机选空闲口）
- 配置文件（`appsettings-<svc>.json`）
- IP 路由表和 DNS 规则文件

Compose 一键管理所有实例。

---

## 备份与回滚（配置层）

### 备份

在交互菜单选择 **6) 备份当前配置文件**，自动备份到 `/opt/openppp2/backups`：

- `appsettings*.json`
- `docker-compose.yml`
- `seccomp-openppp2.json`

### 回滚

在交互菜单选择 **7) 回滚（恢复最新备份）**，自动从最新备份恢复全部配置文件。

也可以从命令行手动操作：

```bash
ls -lt /opt/openppp2/backups/
cp /opt/openppp2/backups/docker-compose.yml.bak.<TS> /opt/openppp2/docker-compose.yml
```

---

## 网络拓扑

### TCP/UDP（默认）模式

```
┌─────────────────┐         ┌─────────────────┐
│   Client Host   │         │   Server Host   │
│                 │         │                 │
│  ┌───────────┐  │         │  ┌───────────┐  │
│  │ openppp2  │  │  UDP    │  │ openppp2  │  │
│  │ container │◄─┼────────►│  │ container │  │
│  │           │  │  20000  │  │           │  │
│  └─────┬─────┘  │         │  └───────────┘  │
│        │ TUN    │         │                 │
│   ┌────▼─────┐  │         │                 │
│   │   ppp0   │  │         │                 │
│   │10.0.0.2  │  │         │                 │
│   └──────────┘  │         │                 │
│                 │         │                 │
│  HTTP: 8080     │         │                 │
│  SOCKS5: 1080   │         │                 │
└─────────────────┘         └─────────────────┘
```

### WebSocket over TLS 模式

`appsettings.base.json` 已经包含 `websocket` 与 `ssl` 段，启用方式：
将 `server` 中的协议改写为 `ppp+wss://your.domain/tun`，并把证书 / 密钥放在
`/opt/openppp2/` 下，重启容器即可走 HTTPS 隧道，更适合在严格的网络环境穿透。

```
┌──────────────┐   HTTPS 443     ┌─────────────────────┐    ┌──────────────┐
│   Client     │ ──────────────► │  Cloudflare / nginx │ ─► │   Server     │
│  openppp2    │  TLS+WebSocket  │   反代 / TLS 终止   │    │  openppp2    │
│  TUN ppp0    │                 │  (可选)             │    │  内网 20000  │
└──────────────┘                 └─────────────────────┘    └──────────────┘
```

> 经反代时需在反代上把 `Upgrade` / `Connection` / `Sec-WebSocket-*` 透传给后端。

---

## 威胁模型与安全边界

**这个项目防御**：

- 上游 release 资产被替换 / CDN 被劫持 → SHA256 校验拒绝构建
- 容器内进程逃逸利用通用 Linux 系统调用 → seccomp 默认 deny，仅放开必要系统调用
- 容器内进程提权 / setuid 滥用 → `no-new-privileges:true` + 非 root 用户 + `cap_drop ALL`
- 容器进程吃光宿主机内存/CPU → `deploy.resources.limits` 兜底
- 容器日志撑爆磁盘 → `logging.options.max-size/max-file` 强制轮转
- 自动更新拉到坏镜像导致服务不可用 → 健康检查 + 自动回滚 + 通知

**这个项目不防御**：

- 宿主机内核被 root 攻陷 / 物理访问 / hypervisor 逃逸 —— 任何容器手段都救不了你
- openppp2 本身的协议层漏洞（如果上游 ppp 二进制本身有 RCE，靠隔离层只能减少二次伤害，不能阻止初次利用）
- 默认密钥未修改的暴力破解 —— **请务必修改** `appsettings.json` 里的 `protocol-key`、`transport-key`、SOCKS5 用户名密码
- 旁路 / 流量分析：本工具不混淆元数据，被动观察者依然能看到「持续的 UDP 流量到某 IP:20000」
- 来自上游 GHCR 注册中心被攻击的供应链风险 —— 进阶可结合 cosign 镜像签名（roadmap）

强烈建议在生产环境补做：

1. 把 `appsettings.json` 中的所有密钥换成 `openssl rand -base64 24` 生成的强随机值
2. 配合 `iptables` / `ufw` 把 `20000` 端口限制在已知客户端 IP 段
3. 设置 `OPENPPP2_UPDATE_WEBHOOK`，更新失败时第一时间知道
4. 用 `:1.0.0.X` 固定 tag 而不是 `:latest`，配合手动升级流程

---

## 故障排查

### 怎么知道我的容器叫什么名字？

服务端默认就一个：`openppp2`。客户端主实例名安装时输入；后续追加的实例名通常是
`openppp2-2`、`openppp2-3`……。要确切看：

```bash
docker compose -f /opt/openppp2/docker-compose.yml ps
# 或者只看名字：
docker ps --filter name=openppp2 --format '{{.Names}}'
```

下文示例中 `<container_name>` 都用上面命令查到的实际名字替换。

### 容器无法启动

```bash
docker compose -f /opt/openppp2/docker-compose.yml logs --tail=200
cat /opt/openppp2/appsettings.json | jq .
docker compose -f /opt/openppp2/docker-compose.yml ps -a
```

### 客户端无法连接服务端

```bash
nc -zv  <服务端IP> 20000     # TCP
nc -zuv <服务端IP> 20000     # UDP

# 服务端检查端口监听
sudo ss -tulnp | grep 20000

# 防火墙
sudo ufw status
sudo iptables -L -n | grep 20000
```

### TUN 设备问题

```bash
ls -l /dev/net/tun
lsmod | grep tun
sudo modprobe tun

CN="$(docker ps --filter name=openppp2 --format '{{.Names}}' | head -1)"
docker exec "$CN" ip link show
```

### io_uring 权限错误

```bash
ls -l /opt/openppp2/seccomp-openppp2.json
grep seccomp /opt/openppp2/docker-compose.yml
# v2.2 的镜像有 HEALTHCHECK，可直接看健康状态：
docker inspect --format '{{json .State.Health}}' openppp2 | jq
```

### 端口冲突

```bash
sudo ss -tulnp | grep <端口号>
sudo lsof -i :<端口号>
vim /opt/openppp2/appsettings.json   # 改 http-proxy.port / socks-proxy.port
cd /opt/openppp2 && docker compose restart
```

### 自动更新出问题

```bash
# 看最近一次更新结果
tail -200 /var/log/openppp2-update.log

# 手动跑一次（不走 timer）
sudo /usr/local/bin/openppp2-update.sh

# 看 timer 状态
systemctl status openppp2-update.timer
systemctl list-timers openppp2-update.timer
```

如果脚本停在 "回滚失败"（exit 2），说明旧镜像 digest 已经被 GC，必须人工指定要回到的 tag：

```bash
cd /opt/openppp2
# 编辑 image: 行指向具体老版本（例如 :1.0.0.25998），然后
docker compose up -d
```

---

## 常见问题

**容器更新后版本没变？**

重启容器（`docker restart`）不会更换镜像。必须 `docker compose up -d --remove-orphans` 重新创建容器。
v2.2 起，自动更新就是按这个流程做的。

**端口冲突？**

脚本自动检测端口占用，从 10000-60000 范围随机选择空闲端口分配。
如果仍有冲突，手动编辑 `appsettings.json` 修改端口。

**Docker 镜像拉取慢？**

安装过程支持临时配置 Docker HTTP 代理。安装完成后代理自动失活（保留配置文件，但不重启 daemon 以保证刚启动的容器不被打断；具体见 install 脚本内的注释段）。

也可以配置 Docker 镜像加速器：

```bash
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": ["https://mirror.gcr.io"]
}
EOF
sudo systemctl restart docker
```

**io_uring 报错 "Operation not permitted"？**

脚本自动生成自定义 seccomp profile 放开 io_uring 相关系统调用。
检查 `docker-compose.yml` 中 `security_opt:` 是否包含 `seccomp=./seccomp-openppp2.json`。

**配置文件中的密钥安全吗？**

`appsettings.base.json` 中的密钥是**示例值，必须修改**：

```bash
openssl rand -base64 24    # 生成强随机密钥
```

修改 `protocol-key`、`transport-key`、SOCKS5 的 `username` / `password`，
并保护好 `appsettings.json` 的文件权限（建议 `chmod 600`）。

**怎么把单实例改成多实例？**

直接在交互菜单选 **3) 新增 openppp2 客户端实例**，脚本会自动分配新 TUN 段、端口、配置。

---

## 开发者指南

### 模块加载顺序

```
config.sh → core.sh → network.sh → seccomp.sh → docker.sh → compose.sh → systemd.sh → backup.sh → client.sh
```

加载顺序至关重要：后续模块依赖前面模块定义的函数。

### 代码质量检查

```bash
# ShellCheck 静态分析
shellcheck install_openppp2.sh lib/*.sh

# 语法检查
bash -n install_openppp2.sh
bash -n lib/*.sh
```

### 本地构建镜像（带校验）

```bash
# 计算上游 zip 的 sha256
curl -fsSL https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip \
  -o /tmp/openppp2.zip
SHA256="$(sha256sum /tmp/openppp2.zip | awk '{print $1}')"

# 带校验值构建
docker build \
  --build-arg OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip" \
  --build-arg OPENPPP2_ZIP_SHA256="$SHA256" \
  -t openppp2-test .

docker run --rm openppp2-test --version
```

---

## 架构概览

```
┌────────────────────────────────────────────┐
│              install_openppp2.sh            │
│          (入口：菜单 + do_install/main)      │
├────────────────────────────────────────────┤
│  config.sh  │  全局常量（路径/镜像/默认值）  │
├─────────────┴──────────────────────────────┤
│                 lib/ 模块层                 │
│  ┌─────────┐ ┌──────────┐ ┌─────────────┐ │
│  │ core    │ │ network  │ │ seccomp     │ │
│  │ 工具函数 │ │ 网络探测  │ │ 安全策略    │ │
│  └────┬────┘ └────┬─────┘ └──────┬──────┘ │
│       └───────────┼──────────────┘         │
│  ┌────────────────┼───────────────────────┐│
│  │          docker.sh                    ││
│  │   daemon · compose检测 · 代理 · 健康检查 ││
│  └────────────────┬──────────────────────┘│
│  ┌────────────────┼───────────────────────┐│
│  │  compose.sh   │    systemd.sh         ││
│  │  YAML 生成     │    timer · boot-delay ││
│  │  (cap/资源)   │    更新+回滚+webhook  ││
│  └────────────────┼───────────────────────┘│
│  ┌────────────────┼───────────────────────┐│
│  │  client.sh    │    backup.sh           ││
│  │  实例管理      │    备份/恢复           ││
│  └────────────────┴───────────────────────┘│
└────────────────────────────────────────────┘
```

---

## 更新日志

### v2.2.0 (2026-05)

- 🔐 **Dockerfile**：下载 ppp 二进制 zip 后强制 SHA256 校验（CI 注入 build-arg）
- 🔐 **Dockerfile**：创建非 root 用户 `ppp(uid=1000)`，`/opt/openppp2` 已 chown，`USER ppp` 默认生效
- 🔐 **Dockerfile**：引入 tini 作为 PID 1，正确处理 SIGTERM 与僵尸子进程
- ❤️ **Dockerfile**：新增 `HEALTHCHECK pgrep -x ppp`，docker ps 直接看健康状态
- 🛡️ **Compose**：`cap_drop: ALL` + `cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]`
- 🛡️ **Compose**：新增 `security_opt: no-new-privileges:true`
- 📊 **Compose**：写入 `deploy.resources.limits`（内存/CPU/软预留），支持环境变量覆盖
- 🔁 **systemd 更新**：先记录 digest → pull → up → 健康检查 → 不健康自动用旧 digest 回滚
- 📬 **systemd 更新**：可选 webhook 通知，配置在 `/etc/default/openppp2-update`
- 📋 **systemd 更新**：所有动作有日志，写入 `/var/log/openppp2-update.log`
- 🎯 **版本管理**：`config.sh` 拆分 `OPENPPP2_IMAGE_REPO` + `OPENPPP2_IMAGE_TAG`，
  支持固定到具体版本而不是只能用 `:latest`
- 🛠️ **代码质量**：`core.sh` 补 `safer_cd/safer_back` 安全切换目录；
  `install_openppp2.sh` 修复所有裸 `cd` 错误处理；新增"延后回收 Docker 代理"
  机制的详细解释注释
- 📖 **README**：架构兼容矩阵、WebSocket+TLS 拓扑图、威胁模型 / 安全边界、
  自动更新与回滚使用说明、扩充故障排查

### v2.1.0

- ✅ 修复所有 ShellCheck 警告（SC2012, SC2164, SC2188, SC2002, SC2086）
- 🔧 优化 CI/CD workflow 逻辑，使用条件执行避免重复构建
- 📦 Dockerfile 改用多阶段构建，减少最终镜像体积
- 📝 增强 README 文档：添加完整部署示例、网络拓扑图、故障排查章节
- 🔢 添加脚本版本号管理（config.sh）
- 🛡️ 改进错误处理：所有 `cd` 命令添加失败检查

### v2.0

- 🔨 模块化重构：主脚本从 1634 行精简至 314 行（−81%）
- 📂 50+ 功能函数按职责拆分至 `lib/` 目录

---

## 日志

- openppp2 日志：`docker compose logs -f <服务名>` 或容器内日志文件
- 安装过程中所有状态信息会输出到终端
- systemd 服务日志：`journalctl -u openppp2-update.service -f`
- 自动更新过程日志：`/var/log/openppp2-update.log`

---

## 贡献

欢迎提交 Issue 和 Pull Request！

在提交 PR 前，请确保：

1. 通过 ShellCheck 检查：`shellcheck install_openppp2.sh lib/*.sh`
2. 在测试环境中验证功能正常
3. 更新相关文档

---

## 许可

本项目脚本和配置按 MIT 许可发布。openppp2 本体按上游 [liulilittle/openppp2](https://github.com/liulilittle/openppp2) 的许可执行。

---

## 致谢

- [openppp2](https://github.com/liulilittle/openppp2) - 上游项目
- 所有贡献者和用户的反馈

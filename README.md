# openppp2-docker

> **v2.2 修复版** —— 修复镜像拉取失败兜底、密钥随机化、真实失败回滚、增强健康检查等问题。

一键安装/更新 openppp2 的 Docker 化部署脚本。支持 Server / Client 双模式、同机多实例、自动更新与配置回滚。

Deploy openppp2 in Docker with one command. Supports server/client modes, multiple client instances, auto-updates with health-gated rollback, and config rollback.

---

## 特性

- 🚀 **一键安装**：自动检测并安装 Docker、Compose 及所有系统依赖
- 🔁 **双模式**：Server / Client，脚本引导式交互配置
- 📦 **多实例**：同机运行多个客户端容器，各自独立的 TUN 设备和配置
- 🛡️ **镜像兜底**：拉取 GHCR 镜像失败时，自动用 Dockerfile 在本机构建（含 ARM64）
- 🔐 **密钥随机化**：每次部署独立随机生成 `protocol-key`/`transport-key`/`kf` 与 SOCKS5 凭据
- 🔄 **自动更新 + 失败回滚**：systemd timer 每周更新，健康检查失败自动回滚到旧镜像并恢复配置
- ❤️ **增强健康检查**：不仅检查容器 Running，还检查 ppp 进程、监听端口、TUN 设备与代理出网
- 🔒 **Seccomp 安全策略**：默认放行 + 显式拒绝高危系统调用，并放行 openppp2 所需的 io_uring
- 🌐 **网络自适应**：自动探测网卡、IP、网关，支持 Docker 代理加速镜像拉取

---

## 前置条件

- **操作系统**：Debian / Ubuntu（推荐），其他 Linux 需手动安装 Docker
- **内核**：Linux 5.1+（io_uring 支持）
- **权限**：root 或 sudo
- **TUN 设备**（Client 模式）：宿主机需支持 `/dev/net/tun`
- **网络**：Client 能访问 Server 的 PPP 端口（默认 UDP+TCP 20000）

---

## 重要：关于镜像与一键安装

本仓库的 `.github/workflows/build.yml` **确实存在**，CI 也在按周运行。但用 `GITHUB_TOKEN` 推送到 GHCR 的容器包**默认是私有（private）的**，匿名 `docker pull` 会失败 —— 这正是"一键安装在拉镜像阶段失败"的根因。

本版本做了两层修复：

1. **CI 层**：workflow 增加了把 GHCR 包设为 public 的步骤，并改为多架构（amd64 + arm64）构建。若该步骤因权限受限失败，请到仓库的 **Packages** 页面把 `openppp2` 包可见性手动改为 **Public**（一次性操作）。
2. **脚本层**：安装脚本不再"拉不到就报错退出"。`ensure_image` 会先尝试 `docker pull`，失败则自动用随仓库附带的 `Dockerfile` 在本机构建镜像（自动识别 amd64/aarch64，从上游 release 下载对应 simd 包）。**即使 GHCR 不可用，一键安装依然能跑通。**

---

## 目录结构

```
openppp2-docker/
├── install_openppp2.sh          # 主入口 — 菜单路由 + 安装/卸载编排层
├── config.sh                    # 集中配置：路径、镜像、默认值、版本号
├── appsettings.base.json        # 基准配置模板（密钥/凭据均为空，安装时生成）
├── Dockerfile                   # 多阶段构建镜像（含 HEALTHCHECK）
├── .dockerignore
├── .github/workflows/build.yml  # CI：按周追踪上游 release，多架构构建并推送 GHCR
└── lib/                         # 模块化函数库（按依赖顺序加载）
    ├── core.sh                  # 核心工具：日志、交互、依赖安装、随机密钥生成
    ├── network.sh               # 网络工具：端口检测、网卡/IP/网关探测、IP 转发
    ├── seccomp.sh               # seccomp 安全策略生成
    ├── docker.sh                # Docker 管理：安装、Compose、代理、镜像兜底构建、健康检查
    ├── compose.sh               # Compose YAML 生成：server / client（多实例注册表驱动）
    ├── systemd.sh               # systemd：每周自动更新（带失败回滚）+ 开机延迟启动
    ├── backup.sh                # 备份与恢复
    └── client.sh                # 客户端操作：新增实例、查看配置、删除实例
```

> ⚠️ 这是一个**模块化**脚本，`install_openppp2.sh` 会 `source` 同目录的 `config.sh` 和 `lib/*.sh`。
> 因此**不能**像旧版那样只 `curl` 单个 `install_openppp2.sh` 运行 —— 必须获取整个仓库。

---

## 快速开始

### 获取项目（务必拉取整个仓库）

```bash
# 方式一：git clone
git clone https://github.com/lucifer988/openppp2-docker.git
cd openppp2-docker
chmod +x install_openppp2.sh

# 方式二：下载 tar 包
curl -fsSL https://github.com/lucifer988/openppp2-docker/archive/refs/heads/main.tar.gz -o openppp2-docker.tar.gz
tar xzf openppp2-docker.tar.gz
cd openppp2-docker-main
chmod +x install_openppp2.sh
```

### 服务端部署

```bash
sudo ./install_openppp2.sh
# 选择 1（服务端）
# 输入公网 IP、监听 IP
# 脚本会随机生成并打印 kf / protocol-key / transport-key
# 这三项会保存到 /opt/openppp2/server-credentials.txt —— 客户端部署时需要
```

### 客户端部署

```bash
sudo ./install_openppp2.sh
# 选择 2（客户端）
# 输入服务端 IP、端口
# 粘贴服务端的 kf / protocol-key / transport-key（必须与服务端完全一致）
# 脚本会随机生成本机 SOCKS5 用户名/密码并打印
```

### 验证运行

```bash
docker compose -f /opt/openppp2/docker-compose.yml ps
docker compose -f /opt/openppp2/docker-compose.yml logs -f
# 客户端测试代理（端口/账号见安装时打印的信息）
curl -x http://<内网IP>:<HTTP端口> https://ifconfig.me
```

### 日常更新

由 systemd timer 每周自动执行（带失败回滚）。手动触发：

```bash
sudo /usr/local/bin/openppp2-update.sh
```

---

## 交互菜单（7 项）

| # | 功能 | 说明 |
| --- | --- | --- |
| 1 | 安装 openppp2 | 交互式配置 Server 或 Client |
| 2 | 卸载 openppp2 | 停止容器、清理 systemd、可选保留备份 |
| 3 | 新增客户端实例 | 在同机追加额外的 client 容器（自动分配 TUN/网段/端口/凭据） |
| 4 | 查看客户端配置 | 列出所有 client 的 server/SOCKS5/HTTP 信息及容器状态 |
| 5 | 删除客户端实例 | 选择并安全移除指定 client 及其配置 |
| 6 | 备份当前配置 | 备份 appsettings\*.json、compose.yml、seccomp 等 |
| 7 | 回滚 | 从最新备份恢复全部配置文件并重启 |

---

## 安全说明（密钥与凭据）

openppp2 的 `key.kf`、`protocol-key`、`transport-key` 是 **server 与 client 必须完全一致** 的强制项；SOCKS5 用户名/密码是客户端本地的。本脚本据此设计：

- **服务端**：随机生成 `kf` / `protocol-key` / `transport-key`，写入并打印到 `/opt/openppp2/server-credentials.txt`（权限 600）。
- **客户端**：安装时**粘贴**服务端的上述三项（脚本不在客户端独立随机这三项，否则握手必然失败）；同时为本机随机生成 SOCKS5 用户名/密码并打印。
- **新增实例（菜单 3）**：自动从已有实例复用共享密钥，SOCKS5 凭据每实例独立随机。

> 基准模板 `appsettings.base.json` 中所有密钥/凭据字段均为空占位，安装流程总会覆盖写入，杜绝"不同用户共用默认密钥"。

---

## 自动更新与回滚（真实回滚）

`/usr/local/bin/openppp2-update.sh` 的流程：

1. 记录当前每个 openppp2 容器使用的镜像 ID 与引用；
2. 备份配置到 `backups/auto-<时间戳>`；
3. `pull` 最新镜像并 `up -d --remove-orphans`；
4. **健康检查**（容器 Running + 容器内存在 ppp 进程）；
5. 若不健康且 `AUTO_ROLLBACK=yes`：把旧镜像 ID 重新 `docker tag` 回原引用、恢复配置、再次 `up`，回到旧版本。

> 这与旧版"只 `pull` + `up`、没有失败回滚"不同 —— 现在是健康检查门控的真实回滚。

---

## 健康检查（增强）

`health_check_one <容器名> [role] [probe]` 的判定层次：

1. 容器进入 Running；
2. 若镜像声明了 HEALTHCHECK，则等待变为 healthy（本仓库 Dockerfile 已加入基于 `pgrep ppp` 的 HEALTHCHECK）；
3. 容器内存在运行中的 ppp 进程；
4. 角色功能探测：
   - **server**：容器内在监听端口（默认 20000）上 LISTEN；
   - **client**：容器内存在 TUN 设备（pppN），并尝试经 HTTP 代理做一次真实出网探测。

> 旧版只检查"容器是否 Running"，无法判断功能是否真的通了。

---

## Seccomp 安全策略

openppp2 使用 io_uring，而部分发行版的 Docker 默认 seccomp 会拒绝 io_uring 相关调用，导致 `Operation not permitted`。

本脚本生成的 `seccomp-openppp2.json` 采用**「默认放行 + 显式拒绝高危调用」**模型：

- `defaultAction` 为 `SCMP_ACT_ALLOW`（不会因白名单不全把 ppp 跑挂）；
- 对一组与容器无关的高危调用（加载内核模块、reboot、kexec、mount/pivot_root、ptrace 等）显式返回 ERRNO 拒绝；
- `io_uring_setup/enter/register` 始终放行。

> 这不是"比 Docker 默认更严格"的白名单策略，而是在"可用"与"有基本防护"之间取平衡。排查问题时可临时改用 `--security-opt seccomp=unconfined`。

---

## 环境变量（无人值守）

```bash
# 指定客户端网卡
DEFAULT_CLIENT_NIC=ens192 sudo ./install_openppp2.sh

# 开机延迟启动（秒，0=禁用）
DEFAULT_BOOT_DELAY=20 sudo ./install_openppp2.sh

# 关闭自动回滚
AUTO_ROLLBACK=no sudo ./install_openppp2.sh

# 兜底构建使用的上游版本（拉不到最新时）
FALLBACK_UPSTREAM_TAG=1.0.0.26016 sudo ./install_openppp2.sh
```

---

## 故障排查

```bash
# 容器无法启动 —— 看日志
docker compose -f /opt/openppp2/docker-compose.yml logs

# 镜像拉取失败 —— 脚本会自动本地构建；手动构建：
cd /opt/openppp2 && docker build -t ghcr.io/lucifer988/openppp2:latest \
  --build-arg OPENPPP2_ZIP_URL=https://github.com/liulilittle/openppp2/releases/download/<tag>/openppp2-linux-amd64-simd.zip .

# io_uring 报 "Operation not permitted" —— 检查 seccomp 是否生效
grep seccomp /opt/openppp2/docker-compose.yml
ls -l /opt/openppp2/seccomp-openppp2.json

# 客户端连不上服务端 —— 确认两端 kf/protocol-key/transport-key 完全一致
diff <(jq .key /opt/openppp2/appsettings.json) <服务端凭据>

# TUN 问题
ls -l /dev/net/tun && lsmod | grep tun
```

---

## 开发者

模块加载顺序（后续模块依赖前面模块定义的函数）：

```
config.sh → core.sh → network.sh → seccomp.sh → docker.sh → compose.sh → systemd.sh → backup.sh → client.sh
```

代码检查：

```bash
shellcheck install_openppp2.sh lib/*.sh
bash -n install_openppp2.sh lib/*.sh
```

---

## 许可

本项目脚本和配置按 MIT 许可发布。openppp2 本体按上游 [liulilittle/openppp2](https://github.com/liulilittle/openppp2) 的许可执行。

## 致谢

- [openppp2](https://github.com/liulilittle/openppp2) — 上游项目

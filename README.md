# openppp2-docker

> **v2.1 优化版** — 修复所有 ShellCheck 警告，优化 CI/CD 逻辑，多阶段构建减少镜像体积，增强文档完整性。

一键安装/更新 openppp2 的 Docker 化部署脚本。支持 Server / Client 双模式、同机多实例、自动更新与配置回滚。

Deploy openppp2 in Docker with one command. Supports server/client modes, multiple client instances, auto-updates, and config rollback.

---

## 特性

- 🚀 **一键安装**：自动检测并安装 Docker、Compose 及所有系统依赖
- 🔀 **双模式**：Server / Client，脚本引导式交互配置
- 📦 **多实例**：同机运行多个客户端容器，各自独立的 TUN 设备和配置
- 🔄 **自动更新**：systemd timer 每周自动拉取最新镜像并重启
- 🛡️ **失败回滚**：配置文件自动备份，出问题一键恢复
- 🔒 **Seccomp 安全策略**：自定义 seccomp profile，仅放开 io_uring 等必要系统调用
- 🌐 **网络自适应**：自动探测网卡、IP、网关，支持 Docker 代理加速镜像拉取
- ✅ **代码质量**：通过 ShellCheck 静态分析，遵循 Shell 最佳实践

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
├── Dockerfile                    # 多阶段构建镜像文件（CI 自动拉取上游 release 构建）
├── .github/workflows/build.yml   # CI：每周日自动追踪上游 release 构建并推送 GHCR
└── lib/                          # 模块化函数库（按依赖顺序加载）
    ├── core.sh                   # 核心工具：日志、交互提示、依赖安装、基础检查
    ├── network.sh                # 网络工具：端口检测、网卡/IP/网关探测、IP 转发
    ├── seccomp.sh                # seccomp 安全策略生成
    ├── docker.sh                 # Docker 管理：daemon 安装、Compose 检测、代理、健康检查
    ├── compose.sh                # Compose YAML 生成：server / client / 追加 / 移除
    ├── systemd.sh                # systemd 集成：开机延迟启动、每周自动更新 timer
    ├── client.sh                 # 客户端操作：新增实例、查看配置、删除实例、交互选择
    └── backup.sh                 # 备份与恢复
```

---

## 快速开始

### 完整部署示例

#### 服务端部署

```bash
# 1. 下载脚本
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o install_openppp2.sh
chmod +x install_openppp2.sh

# 2. 运行安装（选择 1 - 服务端）
sudo ./install_openppp2.sh
# 输入公网 IP: 1.2.3.4
# 输入监听 IP: 1.2.3.4（或内网 IP）

# 3. 验证运行
docker compose -f /opt/openppp2/docker-compose.yml ps
docker compose -f /opt/openppp2/docker-compose.yml logs -f
```

#### 客户端部署

```bash
# 1. 下载脚本（同上）
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o install_openppp2.sh
chmod +x install_openppp2.sh

# 2. 运行安装（选择 2 - 客户端）
sudo ./install_openppp2.sh
# 输入服务端 IP: 1.2.3.4
# 输入服务端端口: 20000

# 3. 验证运行
docker compose -f /opt/openppp2/docker-compose.yml ps
# 测试代理
curl -x http://127.0.0.1:8080 https://ifconfig.me
curl -x socks5://127.0.0.1:1080 https://ifconfig.me
```

### 日常更新

```bash
cd /opt/openppp2
docker compose pull
docker compose up -d --remove-orphans
```

---

## 交互菜单（7 项）

| # | 功能 | 说明 |
|---|------|------|
| 1 | 安装 openppp2 | 交互式配置 Server 或 Client |
| 2 | 卸载 openppp2 | 停止容器、清理 systemd、可选保留备份 |
| 3 | 新增客户端实例 | 在同机追加额外的 client 容器 |
| 4 | 查看客户端配置 | 列出所有 client 的 server/SOCKS5/HTTP 信息 |
| 5 | 删除客户端实例 | 选择并安全移除指定 client 及其配置 |
| 6 | 备份当前配置 | 备份所有 appsettings*.json、compose.yml、seccomp |
| 7 | 回滚 | 从最新备份恢复全部配置文件 |

---

## 环境变量（无人值守）

```bash
# 指定客户端网卡
CLIENT_NIC=ens192 sudo ./install_openppp2.sh

# 开机延迟启动（秒，0=禁用）
OPENPPP2_BOOT_DELAY=20 sudo ./install_openppp2.sh

# 严格开机延迟模式（yes=systemd 全权控制）
STRICT_BOOT_DELAY_MODE=yes sudo ./install_openppp2.sh
```

---

## 多实例（Client）

每个新增实例自动分配独立的：

- TUN 设备名（`ppp2`, `ppp3` ...）
- TUN IP 段（`10.0.2.0/30`, `10.0.3.0/30` ...）
- HTTP / SOCKS5 代理端口（自动探测空闲端口）
- 配置文件（`appsettings-openppp2-N.json`）
- IP 路由表和 DNS 规则文件

Compose 一键管理所有实例。

---

## 备份与回滚

### 备份

在交互菜单选择 **6) 备份当前配置文件**，自动备份到 `/opt/openppp2/backups`：

- `appsettings*.json`
- `docker-compose.yml`
- `seccomp-openppp2.json`

### 回滚

在交互菜单选择 **7) 回滚（恢复最新备份）**，自动从最新备份恢复全部配置文件。

也可以从命令行手动操作：

```bash
# 查看可用备份
ls -lt /opt/openppp2/backups/

# 手动恢复（指定备份时间戳目录下的文件）
cp /opt/openppp2/backups/docker-compose.yml.bak.* /opt/openppp2/docker-compose.yml
```

---

## 网络拓扑

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

---

## 故障排查

### 容器无法启动

```bash
# 查看日志
docker compose -f /opt/openppp2/docker-compose.yml logs

# 检查配置文件
cat /opt/openppp2/appsettings.json | jq .

# 检查容器状态
docker compose -f /opt/openppp2/docker-compose.yml ps -a
```

### 客户端无法连接服务端

```bash
# 测试网络连通性（TCP）
nc -zv <服务端IP> 20000

# 测试 UDP（需要 nc 支持 UDP）
nc -zuv <服务端IP> 20000

# 检查防火墙
sudo ufw status
sudo iptables -L -n | grep 20000

# 服务端检查端口监听
sudo netstat -tulnp | grep 20000
```

### TUN 设备问题

```bash
# 检查 TUN 支持
ls -l /dev/net/tun

# 检查内核模块
lsmod | grep tun

# 手动加载 TUN 模块
sudo modprobe tun

# 检查容器内 TUN 设备
docker exec <container_name> ip link show
```

### io_uring 权限错误

```bash
# 检查 seccomp profile 是否存在
ls -l /opt/openppp2/seccomp-openppp2.json

# 检查 compose 文件是否引用了 seccomp
grep seccomp /opt/openppp2/docker-compose.yml

# 重新生成 seccomp profile
cd /opt/openppp2
sudo ./install_openppp2.sh
# 选择菜单项 6 备份，然后重新安装
```

### 端口冲突

```bash
# 检查端口占用
sudo netstat -tulnp | grep <端口号>
sudo lsof -i :<端口号>

# 修改配置文件中的端口
vim /opt/openppp2/appsettings.json
# 修改 http-proxy.port 和 socks-proxy.port

# 重启容器
docker compose -f /opt/openppp2/docker-compose.yml restart
```

### 日志查看

```bash
# 实时查看所有容器日志
docker compose -f /opt/openppp2/docker-compose.yml logs -f

# 查看特定容器日志
docker compose -f /opt/openppp2/docker-compose.yml logs -f openppp2

# 查看最近 100 行日志
docker compose -f /opt/openppp2/docker-compose.yml logs --tail=100

# 容器内日志文件（如果配置了）
docker exec <container_name> cat /opt/openppp2/ppp.log
```

---

## 常见问题

<details>
<summary><b>容器更新后版本没变？</b></summary>

重启容器 (`docker restart`) 不会更换镜像。必须 `docker compose up -d --remove-orphans` 重新创建容器。
</details>

<details>
<summary><b>端口冲突？</b></summary>

脚本自动检测端口占用，从 10000-60000 范围随机选择空闲端口分配。如果仍有冲突，手动编辑 `appsettings.json` 修改端口。
</details>

<details>
<summary><b>Docker 镜像拉取慢？</b></summary>

安装过程中支持临时配置 Docker HTTP 代理。安装完成后代理自动移除。也可以配置 Docker 镜像加速器：

```bash
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<EOF
{
  "registry-mirrors": ["https://mirror.gcr.io"]
}
EOF
sudo systemctl restart docker
```
</details>

<details>
<summary><b>io_uring 报错 "Operation not permitted"？</b></summary>

脚本自动生成自定义 seccomp profile 放开 io_uring 相关系统调用。如果容器未加载该 profile，
检查 `docker-compose.yml` 中 `security_opt: seccomp=./seccomp-openppp2.json` 是否存在。
</details>

<details>
<summary><b>配置文件中的密钥安全吗？</b></summary>

`appsettings.base.json` 中的密钥是示例值，**必须修改**。建议：
- 使用强随机密钥（可用 `openssl rand -base64 16` 生成）
- 修改 `protocol-key` 和 `transport-key`
- 修改 SOCKS5 的 `username` 和 `password`
- 不要在公开仓库中提交真实密钥
</details>

<details>
<summary><b>如何监控服务状态？</b></summary>

可以使用简单的健康检查脚本：

```bash
#!/bin/bash
# /opt/openppp2/check_health.sh
curl -s http://localhost:8080 >/dev/null && echo "HTTP proxy: OK" || echo "HTTP proxy: FAIL"
curl -s --socks5 localhost:1080 https://ifconfig.me >/dev/null && echo "SOCKS5 proxy: OK" || echo "SOCKS5 proxy: FAIL"
docker compose -f /opt/openppp2/docker-compose.yml ps | grep -q "Up" && echo "Container: OK" || echo "Container: FAIL"
```

配合 cron 定期检查：
```bash
*/5 * * * * /opt/openppp2/check_health.sh >> /var/log/openppp2-health.log 2>&1
```
</details>

---

## 开发者指南

### 模块加载顺序

```
config.sh → core.sh → network.sh → seccomp.sh → docker.sh → compose.sh → systemd.sh → backup.sh → client.sh
```

加载顺序至关重要：后续模块依赖前面模块定义的函数。如需新增模块，插入到正确位置并在 `install_openppp2.sh` 中添加 `source`。

### 代码质量检查

```bash
# ShellCheck 静态分析
shellcheck install_openppp2.sh lib/*.sh

# 语法检查
bash -n install_openppp2.sh
bash -n lib/*.sh
```

### 本地测试

```bash
# 在虚拟机或测试环境中运行
sudo bash install_openppp2.sh

# 使用 Docker 测试镜像构建
docker build -t openppp2-test .
docker run --rm openppp2-test ./ppp --version
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
│  └────────────────┼───────────────────────┘│
│  ┌────────────────┼───────────────────────┐│
│  │  client.sh    │    backup.sh           ││
│  │  实例管理      │    备份/恢复           ││
│  └────────────────┴───────────────────────┘│
└────────────────────────────────────────────┘
```

---

## 更新日志

### v2.1.0 (2024-05-15)

- ✅ 修复所有 ShellCheck 警告（SC2012, SC2164, SC2188, SC2002, SC2086）
- 🔧 优化 CI/CD workflow 逻辑，使用条件执行避免重复构建
- 📦 Dockerfile 改用多阶段构建，减少最终镜像体积
- 📝 增强 README 文档：添加完整部署示例、网络拓扑图、故障排查章节
- 🔢 添加脚本版本号管理（config.sh）
- 🛡️ 改进错误处理：所有 `cd` 命令添加失败检查

### v2.0 (之前)

- 🔨 模块化重构：主脚本从 1634 行精简至 314 行（−81%）
- 📂 50+ 功能函数按职责拆分至 `lib/` 目录
- 🎯 每个模块职责单一、可独立维护和测试

---

## 日志

- openppp2 日志：`docker compose logs -f <service>` 或容器内日志文件
- 安装过程中所有状态信息会输出到终端
- systemd 服务日志：`journalctl -u openppp2-update.service -f`

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

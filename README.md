# openppp2-docker

> **v2.0 模块化重构** — 主脚本从 1634 行精简至 314 行（−81%），50+ 功能函数按职责拆分至 `lib/` 目录，每个模块职责单一、可独立维护和测试。

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
├── config.sh                     # 集中配置：路径、镜像、默认值
├── utils.sh                      # 通用工具：日志、Docker 检查、备份恢复
├── rollback.sh                   # 独立回滚脚本（可脱离主脚本使用）
├── appsettings.base.json         # 基准配置模板（首次安装时据此生成实例配置）
├── Dockerfile                    # 镜像构建文件（CI 自动拉取上游 release 构建）
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

### 1. 下载安装脚本

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o install_openppp2.sh
chmod +x install_openppp2.sh
```

### 2. 运行安装

```bash
sudo ./install_openppp2.sh
```

脚本交互式引导：
- 选择角色（Server / Client）
- 输入服务端 IP / 端口
- 自动探测网卡和 IP（或手动指定）
- 可选：Docker 代理加速、Mux 多路复用

### 3. 日常更新

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

```bash
# 查看可用备份
/opt/openppp2/rollback.sh list

# 恢复最新备份
/opt/openppp2/rollback.sh restore
```

---

## 常见问题

<details>
<summary><b>容器更新后版本没变？</b></summary>

重启容器 (`docker restart`) 不会更换镜像。必须 `docker compose up -d --remove-orphans` 重新创建容器。
</details>

<details>
<summary><b>端口冲突？</b></summary>

脚本自动检测端口占用，从 10000-60000 范围随机选择空闲端口分配。
</details>

<details>
<summary><b>Docker 镜像拉取慢？</b></summary>

安装过程中支持临时配置 Docker HTTP 代理。安装完成后代理自动移除。
</details>

<details>
<summary><b>io_uring 报错 "Operation not permitted"？</b></summary>

脚本自动生成自定义 seccomp profile 放开 io_uring 相关系统调用。如果容器未加载该 profile，
检查 `docker-compose.yml` 中 `security_opt: seccomp=./seccomp-openppp2.json` 是否存在。
</details>

---

## 开发者指南

### 模块加载顺序

```
config.sh → core.sh → network.sh → seccomp.sh → docker.sh → compose.sh → systemd.sh → backup.sh → client.sh
```

加载顺序至关重要：后续模块依赖前面模块定义的函数。如需新增模块，插入到正确位置并在 `install_openppp2.sh` 中添加 `source`。

### 快速 lint

```bash
shellcheck install_openppp2.sh lib/*.sh
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

## 日志

- 安装日志：`/opt/openppp2/install.log`
- openppp2 日志：`docker compose logs -f <service>` 或容器内日志文件

---

## 许可

本项目脚本和配置按 MIT 许可发布。openppp2 本体按上游 [liulilittle/openppp2](https://github.com/liulilittle/openppp2) 的许可执行。

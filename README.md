# openppp2-docker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/shell-bash-4EAA25.svg)](#)
[![Docker](https://img.shields.io/badge/docker-required-2496ED.svg)](#)

把 [openppp2](https://github.com/liulilittle/openppp2) 容器化的一键部署脚本。支持服务端 / 客户端双模式，多客户端实例，systemd 自动更新，配置备份与回滚。

---

## 一键安装

**安装方式只有这一种**。复制下面这一行到你的 Linux 终端，回车即可：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh)
```

> 需要 root 权限。如果你不是 root，请用 `sudo -i` 切到 root 之后再执行。
> 脚本会自动安装 Docker、Compose 插件、jq 等依赖，然后进入交互式菜单。

进入菜单后选择对应操作：

| 项 | 功能 |
|----|------|
| 1 | 安装 openppp2（向导：服务端 / 客户端） |
| 2 | 卸载 openppp2 |
| 3 | 新增客户端实例 |
| 4 | 查看客户端配置与代理信息 |
| 5 | 删除客户端实例 |
| 6 | 备份当前配置 |
| 7 | 回滚到最新备份 |
| 0 | 退出 |

后续维护、再次配置、增删实例等，**也都是同一条命令** —— 重新执行就好：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh)
```

---

## 前置要求

- 操作系统：Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux / Fedora
- 内核：Linux 5.1+（用 `uname -r` 查）—— `io_uring` 需要
- 权限：root（或 `sudo`）
- 客户端模式还需要：宿主机存在 `/dev/net/tun`
- 客户端能访问到服务端的 TCP + UDP 端口（默认 20000）

---

## 特性

- 真正的一键安装：单文件、自包含、`curl | bash` 直接跑
- 自动安装 Docker、Compose 插件、jq 等所有依赖
- 服务端 / 客户端双模式，交互向导式配置
- 多实例：同一台机器可挂多个 client 容器，各自独立 TUN 与代理端口
- 自动探测：网卡 / 内网 IP / 网关 / 空闲端口
- 自定义 seccomp 策略：放开 io_uring 所需系统调用，其余沿用默认拒绝
- systemd 定时器：每周自动 `docker compose pull` + `up -d`
- 备份与回滚：所有配置文件可一键备份，可随时恢复

---

## 安装后

脚本运行完成后：

- 所有文件位于 `/opt/openppp2/`
- 容器名：`openppp2`（主实例），新增实例为 `openppp2-2`、`openppp2-3` ……
- 查看运行状态：`docker ps | grep openppp2`
- 查看日志：`cd /opt/openppp2 && docker compose logs -f`

测试客户端代理是否生效（在客户端机器上）：

```bash
# 假设安装后看到 HTTP=192.168.1.100:38421
curl -x http://192.168.1.100:38421 https://ifconfig.me

# 假设 SOCKS5=192.168.1.100:51002
curl -x socks5h://192.168.1.100:51002 https://ifconfig.me
```

---

## 环境变量（无人值守 / 高级用法）

| 变量 | 说明 | 默认 |
|------|------|------|
| `NON_INTERACTIVE` | 跳过所有 prompt，全部使用默认值 | `no` |
| `APP_DIR` | 安装目录 | `/opt/openppp2` |
| `DEFAULT_IMAGE` | 自定义镜像地址 | `ghcr.io/lucifer988/openppp2:latest` |
| `CLIENT_NIC` | 强制指定客户端网卡（跳过自动探测） | 自动 |
| `OPENPPP2_BOOT_DELAY` | 开机延迟秒数 | `20` |

示例：在不交互的情况下指定网卡安装：

```bash
CLIENT_NIC=ens192 bash <(curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh)
```

---

## 故障排查

**容器起不来** —— 查看日志：

```bash
cd /opt/openppp2 && docker compose logs --tail=200
```

**客户端连不上服务端** —— 检查端口连通性：

```bash
# TCP
nc -zv <服务端IP> 20000
# UDP
nc -zuv <服务端IP> 20000
```

并确认服务端防火墙放行了 20000/tcp 和 20000/udp。

**`io_uring` 报 "Operation not permitted"** —— 确认 seccomp 配置文件存在：

```bash
ls -l /opt/openppp2/seccomp-openppp2.json
grep seccomp /opt/openppp2/docker-compose.yml
```

如果丢了，重新跑一键安装脚本即可重新生成。

**TUN 设备问题** —— 客户端必须有 TUN：

```bash
ls -l /dev/net/tun        # 应该存在
sudo modprobe tun         # 若不存在，加载内核模块
```

**镜像拉取慢** —— 安装过程中脚本会询问是否配置 Docker HTTP 代理；也可以提前配 Docker 镜像加速器：

```bash
sudo mkdir -p /etc/docker
echo '{"registry-mirrors": ["https://mirror.gcr.io"]}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

---

## 卸载

同一条命令进菜单选 **2**：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh)
```

脚本会停掉容器、清理 systemd timer、删除 `/opt/openppp2`（可选择保留 `backups/`），但**不会**卸载 Docker。

---

## 仓库布局

```
openppp2-docker/
├── install_openppp2.sh        # 一键安装脚本（单文件、自包含）
├── appsettings.base.json      # 基准配置模板
├── Dockerfile                 # 多阶段构建镜像
├── .github/workflows/
│   └── build.yml              # 每周追踪上游 release，自动构建并推 GHCR
└── README.md
```

镜像由 GitHub Actions 每周自动构建，标签：

- `ghcr.io/lucifer988/openppp2:latest` —— 最新
- `ghcr.io/lucifer988/openppp2:<version>` —— 指定上游版本

---

## 许可

本仓库脚本与配置：MIT。
openppp2 本体遵循上游 [liulilittle/openppp2](https://github.com/liulilittle/openppp2) 的许可。

---

## 致谢

- 上游项目：[liulilittle/openppp2](https://github.com/liulilittle/openppp2)
- 所有提 issue 与 PR 的人

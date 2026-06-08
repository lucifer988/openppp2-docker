# openppp2-docker

openppp2 Docker 一键部署脚本，支持服务端和客户端快速部署。

## 功能

* 一键安装 openppp2 服务端 / 客户端
* 自动安装 Docker、Docker Compose 和依赖
* 服务端自动生成 `kf`、`protocol-key`、`transport-key`
* 客户端自动生成 HTTP / SOCKS5 代理信息
* 支持新增多个客户端实例
* 支持查看客户端配置和代理信息
* 支持删除客户端实例
* 支持配置备份与回滚
* 支持手动更新
* 更新失败支持自动回滚
* 镜像拉取失败时支持本地构建

## 一键安装

推荐直接安装 **main 当前版本**（你刚上传并维护的就是这套内容）：

```bash
REPO=lucifer988/openppp2-docker
BRANCH=main

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${BRANCH}/install_openppp2.sh" -o install_openppp2.sh

sudo OPENPPP2_REF="${BRANCH}" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" \
  bash install_openppp2.sh
```

## 安装指定正式版本

例如安装 `v2.3.0`：

```bash
REPO=lucifer988/openppp2-docker
TAG=v2.3.0

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/install_openppp2.sh" -o install_openppp2.sh

sudo OPENPPP2_REF="${TAG}" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz" \
  bash install_openppp2.sh
```

## 关于上游 zip 缓存

仓库内的 Actions 会每天检测上游 `liulilittle/openppp2`。若发现新版，会自动缓存：

- 稳定地址：`https://github.com/lucifer988/openppp2-docker/releases/download/upstream-openppp2-cache/openppp2-linux-amd64-simd.zip`
- 版本化地址：`https://github.com/lucifer988/openppp2-docker/releases/download/upstream-openppp2-cache/openppp2-linux-amd64-simd-<上游版本>.zip`

本项目本地构建 Docker 镜像时会优先使用这个缓存地址，而不是直接打上游 release。

## 菜单说明

运行脚本后会出现菜单：

```text
1) 安装 openppp2
2) 卸载 openppp2
3) 新增 openppp2 客户端实例
4) 查看客户端配置和代理信息
5) 删除客户端实例/配置
6) 备份当前配置文件
7) 回滚（恢复最新备份）
```

重新打开菜单：

```bash
sudo bash install_openppp2.sh
```

## 部署服务端

运行脚本：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
1) 安装 openppp2
1) 服务端（Server）
```

按提示输入公网 IP、监听 IP 等信息。

安装完成后会输出：

```text
kf
protocol-key
transport-key
```

这三项是客户端连接服务端必须使用的密钥，请保存好。

服务端密钥保存路径：

```text
/opt/openppp2/server-credentials.txt
```

查看服务端密钥：

```bash
sudo cat /opt/openppp2/server-credentials.txt
```

## 部署客户端

运行脚本：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
1) 安装 openppp2
2) 客户端（Client）
```

按提示输入：

```text
服务端 IP
服务端端口
kf
protocol-key
transport-key
```

其中 `kf`、`protocol-key`、`transport-key` 必须和服务端完全一致。

安装完成后会输出代理信息：

```text
SOCKS5：IP:端口 用户名 密码
HTTP：IP:端口
```

## 新增客户端实例

已部署客户端后，可以继续新增实例：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
3) 新增 openppp2 客户端实例
```

按提示输入实例名称和服务端信息即可。

## 查看客户端代理信息

```bash
sudo bash install_openppp2.sh
```

选择：

```text
4) 查看客户端配置和代理信息
```

## 删除客户端实例

```bash
sudo bash install_openppp2.sh
```

选择：

```text
5) 删除客户端实例/配置
```

## 备份配置

```bash
sudo bash install_openppp2.sh
```

选择：

```text
6) 备份当前配置文件
```

备份目录：

```text
/opt/openppp2/backups
```

## 回滚配置

```bash
sudo bash install_openppp2.sh
```

选择：

```text
7) 回滚（恢复最新备份）
```

## 手动更新

```bash
sudo /usr/local/bin/openppp2-update.sh
```

## 查看运行状态

```bash
cd /opt/openppp2
sudo docker compose ps
```

## 查看日志

查看全部日志：

```bash
cd /opt/openppp2
sudo docker compose logs -f
```

查看指定服务日志：

```bash
cd /opt/openppp2
sudo docker compose logs -f openppp2
```

## 卸载

```bash
sudo bash install_openppp2.sh
```

选择：

```text
2) 卸载 openppp2
```

卸载不会删除 Docker。

## 常用路径

```text
/opt/openppp2                          主目录
/opt/openppp2/docker-compose.yml       Docker Compose 文件
/opt/openppp2/server-credentials.txt   服务端密钥
/opt/openppp2/backups                  备份目录
/usr/local/bin/openppp2-update.sh      手动更新脚本
```

## 可选环境变量

安装时可以通过环境变量覆盖默认配置。

示例：

```bash
NOTIFY_WEBHOOK='https://example.com/hook' IMAGE_KEEP=3 sudo -E bash install_openppp2.sh
```

常用变量：

```text
OPENPPP2_REF             项目版本或分支
OPENPPP2_REPO_TARBALL    项目源码 tar.gz 地址
DOCKER_INSTALL_MIRROR    安装 Docker 时使用的镜像源：auto（默认）/ Aliyun / AzureChinaCloud / none
DOCKER_INSTALL_TIMEOUT   单次 Docker 安装尝试的超时秒数，默认 300（避免网络差时卡死）
IMAGE_KEEP               保留旧镜像数量，默认 2
AUTO_ROLLBACK            更新失败是否自动回滚，默认 yes
NOTIFY_WEBHOOK           更新失败 webhook 通知地址
NOTIFY_EMAIL             更新失败邮件通知地址
LOG_MAX_SIZE             Docker 日志单文件大小，默认 10m
LOG_MAX_FILE             Docker 日志保留数量，默认 3
SELF_UPDATE              是否开启脚本自更新，默认 no
```

## 国内网络 / Docker 安装加速

脚本在检测到未安装 Docker 时，会自动使用官方便捷脚本（`get.docker.com`）安装。

由于官方 Docker 软件源（`download.docker.com`）在国内访问慢、易超时，脚本默认会**自动探测**官方源是否可达：

* 可达：优先官方源安装；
* 不可达（典型的国内网络）：自动改用阿里云镜像（`mirrors.aliyun.com/docker-ce`）安装，并在失败时依次回退到 Azure 中国镜像、官方源。

每次安装尝试都有超时保护，卡住时会自动放弃并换下一种方式，不会无限等待。

如需手动指定镜像源：

```bash
# 强制使用阿里云镜像安装 Docker
sudo DOCKER_INSTALL_MIRROR=Aliyun bash install_openppp2.sh

# 强制使用 Azure 中国镜像
sudo DOCKER_INSTALL_MIRROR=AzureChinaCloud bash install_openppp2.sh

# 强制使用官方源（海外服务器）
sudo DOCKER_INSTALL_MIRROR=none bash install_openppp2.sh

# 调整单次安装超时（秒），默认 300
sudo DOCKER_INSTALL_TIMEOUT=600 bash install_openppp2.sh
```

> 注意：以上镜像仅加速 **Docker 本体的安装**。openppp2 镜像托管在 GHCR（`ghcr.io`），若拉取失败，脚本会自动用 `Dockerfile` 在本机构建作为兜底（无需手动干预）。

## 客户端要求

客户端机器必须支持 TUN。

检查命令：

```bash
ls -l /dev/net/tun
```

如果不存在 `/dev/net/tun`，客户端模式无法运行。

## 说明

默认推荐使用“自动安装最新正式版”的命令。

如果你想固定版本，使用“安装指定版本”。

如果你想测试最新代码，使用“安装 main 分支”。

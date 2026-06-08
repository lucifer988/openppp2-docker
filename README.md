# openppp2-docker 使用说明

## 一键安装最新正式版

```bash
REPO=lucifer988/openppp2-docker

TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
  | head -n 1)"

[ -n "$TAG" ] || {
  echo "获取最新版本失败"
  exit 1
}

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/install_openppp2.sh" -o install_openppp2.sh

sudo OPENPPP2_REF="${TAG}" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz" \
  bash install_openppp2.sh
```

## 安装指定版本

把 `TAG` 改成你要安装的版本号：

```bash
REPO=lucifer988/openppp2-docker
TAG=v2.3.0

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/install_openppp2.sh" -o install_openppp2.sh

sudo OPENPPP2_REF="${TAG}" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz" \
  bash install_openppp2.sh
```

## 安装 main 分支

```bash
REPO=lucifer988/openppp2-docker
BRANCH=main

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${BRANCH}/install_openppp2.sh" -o install_openppp2.sh

sudo OPENPPP2_REF="${BRANCH}" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" \
  bash install_openppp2.sh
```

## 重新打开管理菜单

```bash
sudo bash install_openppp2.sh
```

菜单选项：

```text
1) 安装 openppp2
2) 卸载 openppp2
3) 新增 openppp2 客户端实例
4) 查看客户端配置和代理信息
5) 删除客户端实例/配置
6) 备份当前配置文件
7) 回滚（恢复最新备份）
```

## 部署服务端

运行：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
1) 安装 openppp2
1) 服务端（Server）
```

按提示填写公网 IP、监听 IP、端口等信息。

安装完成后会输出：

```text
kf
protocol-key
transport-key
```

保存服务端密钥：

```bash
sudo cat /opt/openppp2/server-credentials.txt
```

客户端连接服务端时需要使用这三项密钥。

## 部署客户端

运行：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
1) 安装 openppp2
2) 客户端（Client）
```

按提示填写：

```text
服务端 IP
服务端端口
kf
protocol-key
transport-key
```

`kf`、`protocol-key`、`transport-key` 必须和服务端一致。

安装完成后会输出代理信息：

```text
SOCKS5：IP:端口 用户名 密码
HTTP：IP:端口
```

客户端机器需要支持 TUN，检查命令：

```bash
ls -l /dev/net/tun
```

## 新增客户端实例

```bash
sudo bash install_openppp2.sh
```

选择：

```text
3) 新增 openppp2 客户端实例
```

按提示输入实例名称和服务端信息。

## 查看客户端配置和代理信息

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

示例：

```bash
NOTIFY_WEBHOOK='https://example.com/hook' IMAGE_KEEP=3 sudo -E bash install_openppp2.sh
```

常用变量：

```text
OPENPPP2_REF             项目版本或分支
OPENPPP2_REPO_TARBALL    项目源码 tar.gz 地址
IMAGE_KEEP               保留旧镜像数量，默认 2
AUTO_ROLLBACK            更新失败是否自动回滚，默认 yes
NOTIFY_WEBHOOK           更新失败 webhook 通知地址
NOTIFY_EMAIL             更新失败邮件通知地址
LOG_MAX_SIZE             Docker 日志单文件大小，默认 10m
LOG_MAX_FILE             Docker 日志保留数量，默认 3
SELF_UPDATE              是否开启脚本自更新，默认 no
```

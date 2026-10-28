# openppp2-docker 使用说明

## 一键安装最新正式版

```bash
REPO=lucifer988/openppp2-docker
TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name", ""))')"

[ -n "$TAG" ] || { echo "获取最新版本失败" >&2; exit 1; }

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/install_openppp2.sh" -o install_openppp2.sh
sudo env OPENPPP2_REF="$TAG" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz" \
  bash install_openppp2.sh
```

**生产环境建议：**使用正式 Release，不要使用 `main`；确认该版本的 GitHub Actions 镜像构建成功后再部署。

## 安装指定版本

把 `TAG` 改成你要安装的版本号：

```bash
REPO=lucifer988/openppp2-docker
TAG=v2.5.0

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/install_openppp2.sh" -o install_openppp2.sh

sudo env OPENPPP2_REF="${TAG}" \
  OPENPPP2_REPO_TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz" \
  bash install_openppp2.sh
```

## 安装 main 分支（仅测试，不建议生产环境）

```bash
REPO=lucifer988/openppp2-docker
BRANCH=main

curl -fsSL "https://raw.githubusercontent.com/${REPO}/${BRANCH}/install_openppp2.sh" -o install_openppp2.sh

sudo env OPENPPP2_REF="${BRANCH}" \
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
sudo env NOTIFY_WEBHOOK='https://example.com/hook' IMAGE_KEEP=3 bash install_openppp2.sh
```

常用变量：

```text
OPENPPP2_REF             项目版本或分支
OPENPPP2_REPO_TARBALL    项目源码 tar.gz 地址
IMAGE_KEEP               保留旧镜像数量，默认 2
BACKUP_KEEP              保留配置/自动更新快照数量，默认 10
EGRESS_URLS              客户端探测地址列表（空格分隔），默认 https://ifconfig.me
AUTO_ROLLBACK            更新失败是否自动回滚，默认 yes
NOTIFY_WEBHOOK           更新失败 webhook 通知地址
NOTIFY_EMAIL             更新失败邮件通知地址
LOG_MAX_SIZE             Docker 日志单文件大小，默认 10m
LOG_MAX_FILE             Docker 日志保留数量，默认 3
SELF_UPDATE              是否开启脚本自更新，默认 no
```


## 生产部署建议

- 生产环境请安装正式 Release，避免使用 `main`；安装时将镜像通道设置为经灰度验证的固定版本或不可变 digest。镜像更新会重建服务容器并造成短暂连接中断。
- 服务端采用 host 网络，须在云安全组与主机防火墙按实际监听端口放行 TCP/UDP（默认 20000）。客户端 HTTP/SOCKS 代理没有面向公网的认证保护，应限制在可信网络内。
- 上游程序依赖 io_uring；请确认宿主机内核支持且没有被禁用。容器 unhealthy 标记在非 Swarm Docker 中不会自动触发重启，生产环境应配置外部探测和告警。
- Docker daemon 代理配置会重启 Docker，可能影响同机其他容器；共享主机需安排维护窗口。
- 自动更新失败可通过 `journalctl -u openppp2-update.service` 查看。客户端出网检测 URL 可在 `/opt/openppp2/.env` 中设置 `EGRESS_URLS`，以空格分隔多个 URL，任一可用即通过。
- 配置快照默认保留 10 份，可用 `BACKUP_KEEP` 调整。重要凭据请另行加密并离机备份；项目目录内备份不替代灾备。
- 安装器不会自动改写宿主机防火墙、路由或通用内核调优参数。TUN 网段、客户端网卡/网关及 sysctl 参数须按实际主机网络评估。

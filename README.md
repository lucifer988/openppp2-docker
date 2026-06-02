# openppp2-docker

openppp2 Docker 一键部署脚本，当前仅支持 `amd64`。

## 功能

* 一键部署 openppp2 Server / Client
* 自动安装 Docker / Docker Compose 及依赖
* 服务端自动生成 `kf`、`protocol-key`、`transport-key`
* 客户端自动生成 HTTP / SOCKS5 代理信息
* 支持同一台机器新增多个客户端实例
* 支持查看、删除客户端实例
* 支持配置备份与回滚
* 支持定时更新，更新失败自动回滚
* 镜像拉取失败时自动本地构建

## 安装

复制执行：

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/v2.3.0/install_openppp2.sh -o install_openppp2.sh
sudo bash install_openppp2.sh
```

想安装其他版本，把命令里的 `v2.3.0` 改成对应 tag。

## 菜单说明

运行脚本后按菜单选择：

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

选择：

```text
1) 安装 openppp2
1) 服务端（Server）
```

按提示输入公网 IP、监听 IP。

安装完成后会输出：

```text
kf
protocol-key
transport-key
```

这三项是客户端连接服务端必须使用的密钥，请保存好。

密钥也会保存到：

```text
/opt/openppp2/server-credentials.txt
```

查看服务端密钥：

```bash
sudo cat /opt/openppp2/server-credentials.txt
```

## 部署客户端

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

安装完成后脚本会输出本机代理信息：

```text
SOCKS5：IP:端口 用户名 密码
HTTP：IP:端口
```

## 新增客户端实例

已部署客户端后，重新运行脚本：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
3) 新增 openppp2 客户端实例
```

按提示输入新的实例名和服务端信息即可。

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

## 备份与回滚

备份当前配置：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
6) 备份当前配置文件
```

恢复最近一次备份：

```bash
sudo bash install_openppp2.sh
```

选择：

```text
7) 回滚（恢复最新备份）
```

备份目录：

```text
/opt/openppp2/backups
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

```bash
cd /opt/openppp2
sudo docker compose logs -f
```

查看指定实例日志：

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
/opt/openppp2                          配置目录
/opt/openppp2/docker-compose.yml       Docker Compose 文件
/opt/openppp2/server-credentials.txt   服务端密钥
/opt/openppp2/backups                  备份目录
```

## 可选环境变量

安装时可以用环境变量覆盖默认配置，例如：

```bash
NOTIFY_WEBHOOK='https://example.com/hook' IMAGE_KEEP=3 sudo -E bash install_openppp2.sh
```

常用变量：

```text
IMAGE_KEEP        保留旧镜像数量，默认 2
AUTO_ROLLBACK     更新失败是否自动回滚，默认 yes
NOTIFY_WEBHOOK    更新失败 webhook 通知地址
NOTIFY_EMAIL      更新失败邮件通知地址
LOG_MAX_SIZE      Docker 日志单文件大小，默认 10m
LOG_MAX_FILE      Docker 日志保留数量，默认 3
SELF_UPDATE       是否开启脚本自更新，默认 no
```

## 注意

客户端机器必须支持 TUN：

```bash
ls -l /dev/net/tun
```

如果不存在，客户端模式无法运行。

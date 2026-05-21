# openppp2-docker

## 这是做什么的

这是一个用于部署 openppp2 的 Docker 项目。

它通过安装脚本帮助你在服务器上快速创建 openppp2 服务端或客户端容器，并把配置文件、Docker Compose 文件和相关管理操作统一放到 `/opt/openppp2` 目录下。

## 使用方法

### 1. 准备环境

建议使用 Debian / Ubuntu 系统，并使用 root 用户或带 sudo 权限的用户执行。

客户端模式需要系统支持 TUN：

```bash
ls -l /dev/net/tun
```

如果提示不存在，可以尝试：

```bash
sudo modprobe tun
```

### 2. 下载完整项目

不要只下载 `install_openppp2.sh` 单个文件，因为安装脚本还需要同目录下的 `config.sh` 和 `lib/` 目录。

推荐使用 git 下载完整项目：

```bash
cd /root

sudo apt update
sudo apt install -y git

git clone https://github.com/lucifer988/openppp2-docker.git
cd openppp2-docker

chmod +x install_openppp2.sh
```

如果没有 git，也可以下载完整压缩包：

```bash
cd /root

sudo apt update
sudo apt install -y curl tar

curl -L https://github.com/lucifer988/openppp2-docker/archive/refs/heads/main.tar.gz -o openppp2-docker.tar.gz
tar -xzf openppp2-docker.tar.gz
cd openppp2-docker-main

chmod +x install_openppp2.sh
```

### 3. 启动安装脚本

进入项目目录后执行：

```bash
sudo ./install_openppp2.sh
```

脚本会显示主菜单：

```text
1) 安装 openppp2
2) 卸载 openppp2
3) 新增 openppp2 客户端实例
4) 查看客户端配置和代理信息
5) 删除客户端实例/配置
6) 备份当前配置文件
7) 回滚（恢复最新备份）
```

首次部署选择：

```text
1) 安装 openppp2
```

然后脚本会继续让你选择部署角色：

```text
1) 服务端（Server）
2) 客户端（Client）
```

### 4. 安装服务端

服务端机器上执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

操作步骤：

```text
请选择操作：1
请选择安装/部署角色：1
```

后续按提示输入：

```text
镜像地址：直接回车使用默认值
基准配置文件 URL：直接回车使用默认值
服务端配置文件名：默认 appsettings.json
服务端对外公网 IP：填写你的服务端公网 IP
服务端监听 bind IP：如果是直连公网 IP，填公网 IP；如果服务器在 NAT 后面，填内网 IP
```

安装完成后，配置会生成在：

```bash
/opt/openppp2
```

查看容器状态：

```bash
cd /opt/openppp2
sudo docker compose ps
```

查看运行日志：

```bash
cd /opt/openppp2
sudo docker compose logs -f
```

如果你的系统使用旧版 Compose 命令，可以改用：

```bash
sudo docker-compose ps
sudo docker-compose logs -f
```

服务端默认端口通常为：

```text
20000
```

请确保服务端防火墙、安全组或云服务器控制台已经放行 TCP 和 UDP 的对应端口。

### 5. 安装客户端

客户端机器上执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

操作步骤：

```text
请选择操作：1
请选择安装/部署角色：2
```

后续按提示输入：

```text
镜像地址：直接回车使用默认值
基准配置文件 URL：直接回车使用默认值
客户端配置文件名：默认 appsettings.json
主客户端实例名称：默认 openppp2
服务端 IP：填写服务端公网 IP
服务端端口：默认 20000
客户端内网 IP：如果脚本自动检测正确，直接回车；否则手动输入，例如 192.168.1.100
默认网卡名：如果脚本自动检测正确，直接回车；否则手动输入，例如 eth0、ens3、ens192
默认网关：如果脚本自动检测正确，直接回车；否则手动输入，例如 192.168.1.1
是否开启 mux：一般填 no
是否为 Docker 配置 HTTP 代理来拉取镜像：不需要代理填 no，需要代理填 yes
```

客户端安装完成后，脚本会输出类似信息：

```text
SOCKS5：客户端内网IP:随机端口
HTTP ：客户端内网IP:随机端口
```

以后需要查看客户端代理地址，可以重新运行脚本：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

然后选择：

```text
4) 查看客户端配置和代理信息
```

### 6. 新增客户端实例

只有已经以客户端模式安装过的机器，才能新增客户端实例。

执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

选择：

```text
3) 新增 openppp2 客户端实例
```

按提示输入：

```text
镜像地址：直接回车使用默认值
新实例服务名：例如 openppp2-2
新实例配置文件名：例如 appsettings-openppp2-2.json
服务端 IP：填写服务端公网 IP
服务端端口：默认 20000
客户端内网 IP：自动检测正确就回车，否则手动填写
默认网卡名：自动检测正确就回车，否则手动填写
默认网关：自动检测正确就回车，否则手动填写
是否开启 mux：一般填 no
```

完成后脚本会输出该实例的 SOCKS5 和 HTTP 代理地址。

### 7. 查看客户端配置和代理信息

执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

选择：

```text
4) 查看客户端配置和代理信息
```

脚本会列出每个客户端实例的：

```text
服务名
配置文件
服务端地址
bind 地址
SOCKS5 地址
HTTP 地址
```

### 8. 删除客户端实例

执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

选择：

```text
5) 删除客户端实例/配置
```

脚本会列出当前客户端实例，输入要删除的编号即可。

### 9. 备份配置

执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

选择：

```text
6) 备份当前配置文件
```

备份文件会保存到：

```bash
/opt/openppp2/backups
```

### 10. 回滚配置

执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

选择：

```text
7) 回滚（恢复最新备份）
```

恢复后建议重新启动容器：

```bash
cd /opt/openppp2
sudo docker compose up -d
```

如果你的系统使用旧版 Compose 命令：

```bash
cd /opt/openppp2
sudo docker-compose up -d
```

### 11. 卸载

执行：

```bash
cd /root/openppp2-docker
sudo ./install_openppp2.sh
```

选择：

```text
2) 卸载 openppp2
```

脚本会停止并删除 openppp2 容器和相关配置，但不会卸载 Docker。

### 12. 非交互安装示例

如果需要无人值守安装，可以通过环境变量传入参数。

服务端示例：

```bash
cd /root/openppp2-docker

sudo OPENPPP2_NONINTERACTIVE=1 \
  ACTION=1 \
  ROLE=1 \
  SERVER_PUBLIC_IP=1.2.3.4 \
  SERVER_BIND_IP=1.2.3.4 \
  ./install_openppp2.sh
```

客户端示例：

```bash
cd /root/openppp2-docker

sudo OPENPPP2_NONINTERACTIVE=1 \
  ACTION=1 \
  ROLE=2 \
  SERVER_IP=1.2.3.4 \
  SERVER_PORT=20000 \
  CLIENT_NIC=eth0 \
  USE_MUX=no \
  USE_PROXY=no \
  ./install_openppp2.sh
```

其中：

```text
ACTION=1 表示安装
ROLE=1 表示服务端
ROLE=2 表示客户端
SERVER_IP 是服务端 IP
SERVER_PORT 是服务端端口
CLIENT_NIC 是客户端默认网卡名
```

### 13. 常用命令

进入配置目录：

```bash
cd /opt/openppp2
```

查看容器：

```bash
sudo docker compose ps
```

查看日志：

```bash
sudo docker compose logs -f
```

重启容器：

```bash
sudo docker compose restart
```

停止容器：

```bash
sudo docker compose down
```

重新启动容器：

```bash
sudo docker compose up -d
```

查看配置文件：

```bash
ls -lah /opt/openppp2
```

查看主配置：

```bash
cat /opt/openppp2/appsettings.json
```

如果你的系统使用旧版 Compose 命令，把上面的 `docker compose` 改成 `docker-compose` 即可。

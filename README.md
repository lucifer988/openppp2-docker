# openppp2-docker hotfix 2.3.1

这是按你实际报错改好的 hotfix 版本。

## 修复了什么

1. `apt update` 被 Caddy / Cloudsmith 源 `NO_PUBKEY ABA1F9B8875A6661` 拖垮时，脚本会自动把 `/etc/apt/sources.list.d/*caddy*` 临时挪到 `/root/disabled-apt-sources/`，然后重试。
2. `/opt/openppp2/appsettings.json` 如果已经被误创建成目录，脚本会自动备份挪走，不再报 `Is a directory`。
3. `docker compose` 不再被当成一个带空格的可执行文件执行，修复 `timeout: failed to run command ‘docker compose’: No such file or directory`。
4. 本地构建默认下载 `openppp2 1.0.0.26151`，避免旧地址 `1.0.0.26016` 返回 404。
5. 生成的 Compose 文件使用 long syntax bind mount，并设置 `create_host_path: false`，避免配置文件不存在时 Docker/Compose 又创建同名目录。

## 使用方法

把压缩包上传到服务器后执行：

```bash
cd /root
tar -xzf openppp2-docker-hotfix-2.3.1.tar.gz
cd openppp2-docker-hotfix-2.3.1
chmod +x install_openppp2.sh
sudo ./install_openppp2.sh
```

服务端选择：

```text
1) 安装 openppp2
1) 服务端（Server）
```

客户端选择：

```text
1) 安装 openppp2
2) 客户端（Client）
```

## 可覆盖变量

```bash
# 指定镜像
sudo OPENPPP2_IMAGE_REPO=ghcr.io/lucifer988/openppp2 OPENPPP2_IMAGE_TAG=latest ./install_openppp2.sh

# 指定本地构建时 openppp2 zip 下载地址
sudo OPENPPP2_ZIP_URL=https://github.com/liulilittle/openppp2/releases/download/1.0.0.26151/openppp2-linux-amd64-simd.zip ./install_openppp2.sh

# 禁止本地构建，只允许 pull 镜像
sudo ALLOW_LOCAL_BUILD=no ./install_openppp2.sh
```

## 常用命令

```bash
cd /opt/openppp2
sudo docker compose ps
sudo docker compose logs -f
sudo docker compose up -d
sudo docker compose down
```

如果系统只有旧版 Compose：

```bash
sudo docker-compose ps
sudo docker-compose logs -f
```

## 注意

这个 hotfix 包重点修复你当前安装链路。菜单中的「新增客户端实例」和「删除客户端实例」为了避免误改现有 TUN/路由，已改成提示信息，不自动执行多实例变更。

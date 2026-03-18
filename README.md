# openppp2-docker

一键安装/更新 openppp2 的 Docker 化部署脚本，支持 server/client、多实例、自动更新与回滚。

## 特性

- 一键安装（自动准备 Docker/Compose 与依赖）
- server/client 模式
- 多实例（同机多个 client 容器）
- 自动生成 `docker-compose.yml`
- 自动配置 systemd 定时更新
- 失败回滚（配置备份/恢复）

## 目录结构

- `install_openppp2.sh` 一键安装/更新脚本（主入口）
- `config.sh` 默认配置集中管理
- `appsettings.base.json` 基准配置模板
- `rollback.sh` 回滚脚本（恢复最新备份）
- `utils.sh` 工具函数库（日志、Docker 检查、备份/恢复）
- `Dockerfile` 镜像构建文件（如需自建）

## 快速开始

### 1. 下载安装脚本

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o install_openppp2.sh
chmod +x install_openppp2.sh
```

### 2. 安装（交互式）

```bash
sudo ./install_openppp2.sh
```

脚本会引导选择模式（server/client）、端口、网卡、是否使用 Docker 代理等。

### 3. 更新

如果使用脚本生成的 `docker-compose.yml`：

```bash
cd /opt/openppp2
docker compose pull
docker compose up -d --remove-orphans
```

如果是独立容器：

```bash
docker pull ghcr.io/lucifer988/openppp2:latest
# 重启你的容器
```

## 一键脚本常用项

安装脚本支持环境变量覆盖，便于无人值守：

```bash
# 示例：指定客户端网卡、开机延迟
CLIENT_NIC=ens192 OPENPPP2_BOOT_DELAY=20 sudo ./install_openppp2.sh
```

常用变量：

- `CLIENT_NIC` 默认客户端网卡（不存在会自动探测）
- `OPENPPP2_BOOT_DELAY` 开机延迟秒数（0 禁用）
- `STRICT_BOOT_DELAY_MODE` 是否由 systemd 全权控制启动（yes/no）

## 多实例（client）

脚本会为每个实例生成：

- `appsettings-openppp2-*.json`
- 对应的 `docker-compose.yml` service

更新/重启时可通过 compose 一键处理所有实例。

## 回滚


## 备份与回滚

安装脚本现在会在写入以下文件前自动备份到 `/opt/openppp2/backups`：

- `appsettings*.json`
- `docker-compose.yml`
- `seccomp-openppp2.json`

卸载时会提示是否保留备份目录；选择保留则仅清理应用文件。

查看备份：

```bash
/opt/openppp2/rollback.sh list
```

恢复最新备份：

```bash
/opt/openppp2/rollback.sh restore
```
查看备份：

```bash
/opt/openppp2/rollback.sh list
```

恢复最新备份：

```bash
/opt/openppp2/rollback.sh restore
```

## 常见问题

### 1) 为什么容器更新后版本没变？

重启容器不会自动换镜像，需要 `docker compose up -d --remove-orphans` 重新创建容器。

### 2) 端口冲突怎么办？

脚本会检测端口占用并自动选择空闲端口，或提示你更换。

### 3) Docker 拉取慢怎么办？

安装脚本支持临时设置 Docker 代理，按提示输入即可。

## 日志

- 安装日志：`/opt/openppp2/install.log`
- openppp2 日志：容器内或映射到本地（取决于配置）

## 许可

按原仓库/上游项目许可执行。

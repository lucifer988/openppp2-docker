# Hotfix change log

## 2.3.2-hotfix

继续针对实际安装日志修复：

- 默认 Compose 安全配置改为 `seccomp=unconfined`，避免过严 seccomp profile 导致 `cannot start a stopped process`。
- `compose_up` 会先 `down --remove-orphans`，再 `up -d --force-recreate --remove-orphans`，避免旧容器沿用旧配置。
- 安装失败时自动输出容器列表和 inspect state，方便定位问题。

## 2.3.1-hotfix

- 修复 Caddy APT 源缺少公钥导致 `apt update` 失败。
- 修复 `/opt/openppp2/appsettings.json` 是目录时 `jq > appsettings.json` 报 `Is a directory`。
- 修复把 `"docker compose"` 当成单个命令传给 `timeout` 导致 `No such file or directory`。
- 修复 Dockerfile 默认下载 `1.0.0.26016` 404，改为 `1.0.0.26151`。
- Compose bind mount 改为 long syntax，设置 `create_host_path: false`。
- 安装脚本改为单文件自包含，减少模块调用问题。

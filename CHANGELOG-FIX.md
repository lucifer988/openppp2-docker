# Hotfix change log

## 2.3.1-hotfix

针对实际安装日志修复：

- 修复 Caddy APT 源缺少公钥导致 `apt update` 失败。
- 修复 `/opt/openppp2/appsettings.json` 是目录时 `jq > appsettings.json` 报 `Is a directory`。
- 修复把 `"docker compose"` 当成单个命令传给 `timeout` 导致 `No such file or directory`。
- 修复 Dockerfile 默认下载 `1.0.0.26016` 404，改为 `1.0.0.26151`。
- Compose bind mount 改为 long syntax，设置 `create_host_path: false`。
- 安装脚本改为单文件自包含，减少模块调用问题。

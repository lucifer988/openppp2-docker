# openppp2-docker

一键脚本部署 openppp2（仅支持 amd64）。支持 Server / Client 双模式、同机多实例、自动更新与失败回滚。
镜像固定到不可变 digest（可复现）、容器能力最小化、运行时资源/日志均设上限、自动更新失败有通知与回滚。

## 安装

在 root（或 sudo）下，下载主脚本并运行即可。脚本会自动安装 Docker/Compose 及依赖；
检测到缺少 `lib/` 模块时，会自动从**固定 tag**（非 main 分支）拉取完整项目并重新执行，保证可复现：

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/v2.4.0/install_openppp2.sh -o install_openppp2.sh
sudo bash install_openppp2.sh
```

> 想装别的版本：把上面 URL 里的 `v2.4.0` 换成对应 tag，或运行时设 `OPENPPP2_REF=<tag>`。

运行后按菜单操作：

```
1) 安装 openppp2          # 选 1=服务端 / 2=客户端，按提示输入
2) 卸载 openppp2
3) 新增 openppp2 客户端实例
4) 查看客户端配置和代理信息
5) 删除客户端实例/配置
6) 备份当前配置文件
7) 回滚（恢复最新备份）
```

### 服务端

选择 `1` → `1`（服务端），输入公网 IP / 监听 IP。脚本会随机生成并打印 `kf` / `protocol-key` / `transport-key`（同时保存到 `/opt/openppp2/server-credentials.txt`，权限 600），**客户端安装时需要这三项**。

### 客户端

选择 `1` → `2`（客户端），输入服务端 IP / 端口，并粘贴服务端的 `kf` / `protocol-key` / `transport-key`（必须完全一致）。脚本会随机生成本机 SOCKS5 用户名/密码并打印。

## 镜像

默认发现通道 `ghcr.io/lucifer988/openppp2:latest`，由 GitHub Actions（buildx）构建并推送到 GHCR：

- 镜像内 `ppp` 二进制来自上游 `liulilittle/openppp2` 的 release，构建时按 **SHA256 校验**；
- 推送前有**冒烟测试门禁**：本地构建后先验证镜像内 `ppp` 能在 amd64 上正常执行、`pgrep` 存在，通过才推送；
- 随镜像附带 **SBOM 与 provenance** 证明；
- 镜像用 **cosign keyless（OIDC）** 签名，可验证来源：

```bash
cosign verify ghcr.io/lucifer988/openppp2:latest \
  --certificate-identity-regexp 'https://github.com/lucifer988/openppp2-docker/.github/workflows/build.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

> 拉取失败时安装脚本会自动用仓库内 `Dockerfile` 在本机构建（同样做 SHA256 校验），即使 GHCR 不可用也能装成功。
> 首次发布后需在 GHCR 包设置里把可见性手动改为 **Public**（GitHub 不提供改可见性的 REST API），匿名 `docker pull` 才可用，设一次即可。

### 镜像固定（可复现）

为避免 `:latest` 漂移牺牲可复现性，安装时会把运行镜像**固定到不可变 digest**（`repo@sha256:...`）写入 `docker-compose.yml` 与 `${APP_DIR}/.image`；浮动标签仅记录在 `${APP_DIR}/.image_channel`，**只用于自动更新时"发现"新版本**。这样开机/日志轮转触发的容器重建始终用同一份镜像，不会悄悄换版本。

## 自动更新与运维

- **受控更新 + 健康门控回滚**：每周定时任务通过 `.image_channel` 发现上游新镜像 → 切换到其 digest → 健康检查（容器 + ppp 进程 + HEALTHCHECK + 真实出网/监听探测，最多重试 6 次）→ **通过才保留，失败自动回滚**到旧 digest 并恢复配置（可用 `AUTO_ROLLBACK=no` 关闭）。
- **灰度铺开**：timer 带 `RandomizedDelaySec=1h` 抖动，避免大批机器同一秒一起拉镜像/重建（惊群与上游限流）；跨机更严格的金丝雀可错开各机 `OnCalendar`。
- **失败通知**：更新/轮转单元配置了 `OnFailure`，失败时一定写 journald（`journalctl -u openppp2-update.service`），并可选推送到 **webhook**（`NOTIFY_WEBHOOK`，发送通用 `{"text":...}` JSON）或**邮件**（`NOTIFY_EMAIL`，需宿主机有 `mail`）。
- **旧镜像清理**：更新成功后按 `IMAGE_KEEP`（默认 2 = 当前 + 上一个供回滚）保留，其余自动 `docker rmi`。
- **脚本自更新（默认关闭）**：`SELF_UPDATE=yes` 时，更新任务会先检查本仓库是否有更高的 release tag，有则下载该 tag 并**仅刷新 systemd 助手脚本/单元**（不动配置与容器）。⚠ 这会让 root 自动执行公网下载的新脚本，请自行评估供应链风险后再开启。
- **配置持久化**：上述可调项在安装时落盘到 `${APP_DIR}/.env`（权限 600），自动更新/自更新在无人值守地重新生成 systemd 助手时会复用它们。
- **手动更新**：随时运行 `sudo /usr/local/bin/openppp2-update.sh`（或 `systemctl start openppp2-update.service`）即可走同一套"更新→健康检查→失败回滚"的流程。

所有可调项均可在安装时用环境变量覆盖，例如：

```bash
NOTIFY_WEBHOOK='https://example.com/hook' MEM_LIMIT=2g IMAGE_KEEP=3 \
  SELF_UPDATE=yes sudo -E bash install_openppp2.sh
```

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `MEM_LIMIT` | `1g` | 容器内存上限（空=不限） |
| `PIDS_LIMIT` | `4096` | 进程/线程数上限（openppp2 多线程，勿设过低；空=不限） |
| `CPUS` | 空 | CPU 配额，如 `1.5`（默认不限，避免限制吞吐） |
| `IMAGE_KEEP` | `2` | 本机保留的旧镜像份数 |
| `AUTO_ROLLBACK` | `yes` | 更新健康检查失败是否自动回滚 |
| `NOTIFY_WEBHOOK` / `NOTIFY_EMAIL` | 空 | 更新/轮转失败通知 |
| `SELF_UPDATE` | `no` | 是否开启脚本自更新 |
| `LOG_MAX_SIZE` / `LOG_MAX_FILE` | `10m` / `3` | 容器 json 日志滚动 |

## 安全说明

- **密钥随机化**：`protocol-key` / `transport-key` / `kf` 由服务端随机生成，客户端复用；SOCKS5 凭据每实例独立随机。
- **文件权限**：脚本以 `umask 077` 运行，含密钥的 `appsettings*.json`、凭据、`.env`、备份等均为 `600`（仅 root 可读）。
- **能力最小化**：容器虽仍以 root 运行（host 网络下创建 TUN/改路由/iptables 需要），但 `cap_drop: ALL` 后只保留 `NET_ADMIN` 与 `NET_RAW`，并加 `no-new-privileges:true` 阻止 setuid 提权。
- **资源上限**：`mem_limit` / `pids_limit`（可选 `cpus`）防止异常实例拖垮宿主机。
- **HEALTHCHECK**：镜像内置基于 `pgrep ppp` 的健康检查，配合外层脚本的端口/出网探测。
- **seccomp**：以 Docker 默认 allowlist（`SCMP_ACT_ERRNO` 默认拒绝）为基线，仅额外放行 openppp2 必需的 `io_uring_*` 三个系统调用（见 `lib/seccomp.sh`）。排查时可临时用 `--security-opt seccomp=unconfined`。

## 开发

```bash
shellcheck -x --severity=warning install_openppp2.sh config.sh lib/*.sh
shfmt -i 2 -ci -d install_openppp2.sh config.sh lib/*.sh
bats tests/
```

CI（`.github/workflows/lint.yml`）会自动跑上述三项；`build.yml` 负责构建/扫描/签名/发布镜像；`release.yml` 在打 `vX.Y.Z` tag 时创建正式 Release。

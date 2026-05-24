# openppp2-docker

一键脚本部署 openppp2（仅支持 amd64）。支持 Server / Client 双模式、同机多实例、自动更新与失败回滚。

## 安装

在 root（或 sudo）下，下载主脚本并运行即可。脚本会自动安装 Docker/Compose 及依赖；
检测到缺少 `lib/` 模块时，会自动从**固定 tag**（非 main 分支）拉取完整项目并重新执行，保证可复现：

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/v2.3.0/install_openppp2.sh -o install_openppp2.sh
sudo bash install_openppp2.sh
```

> 想装别的版本：把上面 URL 里的 `v2.3.0` 换成对应 tag，或运行时设 `OPENPPP2_REF=<tag>`。

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

默认镜像 `ghcr.io/lucifer988/openppp2:latest`，由 GitHub Actions（buildx）构建并推送到 GHCR：

- 镜像内 `ppp` 二进制来自上游 `liulilittle/openppp2` 的 release，构建时按 **SHA256 校验**；
- 随镜像附带 **SBOM 与 provenance** 证明；
- 镜像用 **cosign keyless（OIDC）** 签名，可验证来源：

```bash
cosign verify ghcr.io/lucifer988/openppp2:latest \
  --certificate-identity-regexp 'https://github.com/lucifer988/openppp2-docker/.github/workflows/build.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

> 拉取失败时安装脚本会自动用仓库内 `Dockerfile` 在本机构建（同样做 SHA256 校验），即使 GHCR 不可用也能装成功。
> 首次发布后需在 GHCR 包设置里把可见性手动改为 **Public**（GitHub 不提供改可见性的 REST API），匿名 `docker pull` 才可用，设一次即可。

## 安全说明

- **密钥随机化**：`protocol-key` / `transport-key` / `kf` 由服务端随机生成，客户端复用；SOCKS5 凭据每实例独立随机。
- **文件权限**：脚本以 `umask 077` 运行，含密钥的 `appsettings*.json`、凭据、备份等均为 `600`（仅 root 可读）。
- **seccomp**：以 Docker 默认 allowlist（`SCMP_ACT_ERRNO` 默认拒绝）为基线，仅额外放行 openppp2 必需的 `io_uring_*` 三个系统调用（见 `lib/seccomp.sh`）。排查时可临时用 `--security-opt seccomp=unconfined`。
- **自动更新**：systemd 定时器带 `RandomizedDelaySec` 抖动、`flock` 串行化；更新后做健康检查（容器 + ppp 进程 + HEALTHCHECK + 真实出网/监听），失败自动回滚到旧镜像。

## 开发

```bash
shellcheck -x --severity=warning install_openppp2.sh config.sh lib/*.sh
shfmt -i 2 -ci -d install_openppp2.sh config.sh lib/*.sh
bats tests/
```

CI（`.github/workflows/lint.yml`）会自动跑上述三项；`build.yml` 负责构建/扫描/签名/发布镜像；`release.yml` 在打 `vX.Y.Z` tag 时创建正式 Release。

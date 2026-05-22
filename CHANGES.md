# 修复说明（CHANGES）

本文档总结针对 `lucifer988/openppp2-docker` 报告的四个问题的核查结论与修复，以及自查发现并修复的额外问题。

---

## ⚠️ 重要透明性说明

本次交付环境**无法直接从 GitHub 拉取仓库内的 `lib/*.sh` 八个模块文件**（沙箱网络受限，且这些文件的 blob 链接未出现在可抓取的页面里）。

因此 `lib/` 下的模块是依据以下**完全可获取**的材料**忠实重建**的：

- 完整的 `install_openppp2.sh`（编排层，定义了每个 lib 函数的名字、参数与调用方式）；
- `README.md`（功能与菜单行为说明）；
- `config.sh`、`appsettings.base.json`、`Dockerfile`、`build.yml`；
- 上游 `liulilittle/openppp2` 的命令行与配置参考。

重建过程严格对齐原编排层要求的函数签名与状态文件约定。**建议你拿到后与自己仓库里的原始 `lib/*.sh` 做一次 `diff` 核对**，确认行为一致后再上线。

---

## 报告的四个问题

### 1. CI/GHCR 镜像与一键安装失败 —— 前提部分有误，但结论成立

**核查**：`.github/workflows/build.yml` **确实存在**，CI 也按周运行过多次。你看到 404、且 Packages 区为空，根因不是"没有 workflow"，而是：用 `GITHUB_TOKEN` 推送到 GHCR 的容器包**默认是私有（private）**，workflow 里**从未把它设为 public**，导致匿名 `docker pull` 失败、Packages 对外不可见。

所以你的最终担心（镜像不公开 → 一键安装大概率在拉镜像阶段失败）**是成立的**。

**修复**：
- workflow 增加把 GHCR 包设为 public 的步骤（REST API，失败则提示一次性手动设置）；
- 安装脚本新增 `ensure_image`：`docker pull` 失败时自动用 `Dockerfile` 在本机构建，**即使 GHCR 不可用也能装成功**。

### 2. 硬编码密钥与默认 SOCKS 凭据 —— 确认，已修复

**核查**：`appsettings.base.json` 里 `protocol-key`、`transport-key` 为固定值，SOCKS5 为 `test/123456`，证书密码为 `test`；原安装脚本只改 IP/server/guid/端口，**未随机化密钥**。

**修复**：
- `appsettings.base.json` 中所有密钥/凭据字段清空为占位；
- **服务端**随机生成 `kf`/`protocol-key`/`transport-key`，打印并写入 `server-credentials.txt`（600 权限）；
- **客户端**安装时粘贴服务端这三项（强制一致，否则握手失败），并为本机随机生成 SOCKS5 用户名/密码；
- 多实例新增时，SOCKS5 凭据每实例独立随机。

> 关键点：`kf`/`protocol-key`/`transport-key` 是 server/client 必须一致的强制项，**不能两端各自随机**，只能由服务端生成、客户端复用。

### 3. 自动更新/回滚名实不符 —— 确认，已修复

**核查**：原 systemd 更新脚本只做 `pull` + `up -d --remove-orphans`，**没有健康检查失败后的自动回滚**。

**修复**：`openppp2-update.sh` 改为：快照旧镜像 ID + 备份配置 → 更新 → **健康检查（重试至多 6 次：容器 Running + ppp 进程 + 客户端经 HTTP/SOCKS5 代理真实出网 + 服务端 TCP/UDP 监听）** → 失败时把旧镜像重新 `tag` 回去、恢复配置、再次 `up`，实现**健康检查门控的真实回滚**（可用 `AUTO_ROLLBACK=no` 关闭）。

### 4. 健康检查偏弱 —— 确认，已修复

**核查**：原 `health_check_one` 只看容器是否 Running；Dockerfile 无 HEALTHCHECK。

**修复**：
- `health_check_one` 增强为：Running →（若有）HEALTHCHECK healthy → 容器内 ppp 进程存在 → 角色探测：
  - **server**：容器内 TCP **和** UDP 端口都在监听；
  - **client**：容器内有 TUN 设备，且宿主机经 **HTTP** 代理与 **SOCKS5（socks5h）** 代理各做一次真实出网探测（`curl --max-time 10`）；
- Dockerfile 加入基于 `pgrep ppp` 的 HEALTHCHECK，并安装 `procps`/`iproute2` 以支持容器内探测。

---

## 自查发现并修复的额外问题

- **一键安装命令本身不可用**：仓库已是模块化结构（`source lib/*.sh`），但 README 仍教用户只 `curl` 单个 `install_openppp2.sh` 运行，必然因找不到模块而失败。README 已改为 `git clone` / 下载 tar 包获取整个仓库。
- **README 对 seccomp 的描述不准确**：实际是"默认放行 + 显式拒绝高危调用"，并非"比 Docker 默认更严格的白名单"。文档已据实更正。
- **compose 相对路径**：`security_opt: seccomp=./...` 按 CLI 的工作目录解析，`compose()` 封装已确保始终在 `APP_DIR` 下执行。
- **客户端 TUN 默认名**：上游 Linux 默认 `ppp`，脚本对主实例用 `ppp0`、多实例用 `pppN`，并通过命令行参数显式指定，避免歧义。
- **卸载健壮性**：清理全部 `openppp2*` 容器（含多实例）、systemd 单元与 sysctl 配置；保留备份选项时二次确认无运行容器。

---

## 版本

- config.sh：`SCRIPT_VERSION` 由 `2.1.0` → `2.2.0`
- 新增文件：`.dockerignore`、`CHANGES.md`，以及设包为 public 的 `build.yml`（仅 amd64）

## 已做的校验

- 全部 `*.sh` 通过 `bash -n` 语法检查；
- systemd 生成的 `openppp2-stack.sh`/`openppp2-update.sh`/`openppp2-wait-uptime.sh` 在临时目录实际生成后再次通过 `bash -n`；
- `appsettings.base.json` 通过 JSON 解析校验，且确认所有密钥/凭据字段为空；
- `build.yml` 通过 YAML 解析校验；
- 多实例 `docker-compose.yml` 渲染结果通过 YAML 解析，命令行参数数组、mux 行、TUN/网段、host 网络与 `/dev/net/tun` 设备均符合预期；
- 服务端/客户端的 JSON 生成逻辑经等价校验：密钥被正确随机化、SOCKS 凭据不再是 `test/123456`、且 client 与 server 的强制密钥一致。

> 注：本环境未安装 `shellcheck` 且离线无法安装，故未跑 shellcheck；上线前建议你本地再跑一次 `shellcheck install_openppp2.sh lib/*.sh`。

---

## 追加修复（运行实测反馈）

### A. Docker 安装失败即退出 —— 已修复
**现象**：`curl -fsSL https://get.docker.com | sh` 在部分网络（如国内）会 `Connection reset by peer`，脚本随即 `die`，安装中断。

**根因**：① 只试官方脚本一条路，无重试、无备选源；② `curl | sh` 管道在中途断流时可能执行残缺脚本。

**修复**（`lib/docker.sh`）：新增 `install_docker` 多渠道安装，依次尝试并任一成功即继续：
1. 官方脚本：先 `curl --retry 3` 下载到本地文件、校验非空后再 `sh` 执行（不再边下边执行）；
2. 发行版软件源：`apt-get install docker.io` + Compose 插件（`docker-compose-v2` / `docker-compose-plugin` / `docker-compose` 逐级回退）；国内通常比 get.docker.com 更稳；
3. RHEL 系 `dnf`/`yum` 兜底。
全部失败才报错，并给出明确的手动安装指引。安装后增加守护进程就绪等待（最多 ~15s）。

### B. 依赖检测把"包名"当"命令"，每次都跑 apt —— 已修复
**现象**：日志总是出现 `[INFO] 安装依赖：ca-certificates iproute2`，即便它们已是最新。

**根因**：`ensure_pkgs` 用 `command -v <名字>` 判断是否已装，但 `ca-certificates`、`iproute2` 是**包名不是命令**，`command -v` 必然失败，于是每次都触发 apt。

**修复**（`lib/core.sh`）：`ensure_pkgs` 改为按**真实命令/文件**判断——`iproute2` 探测 `ip`、`ca-certificates` 探测 `/etc/ssl/certs`；命令已存在则完全跳过 apt（实测：`ip` 与证书目录都在时不再触发任何 apt 调用）。同时补充 `dnf`/`yum` 分支。

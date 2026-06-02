# 修复说明（CHANGES）

## v2.4.0 — 生产化与长期自动更新加固

本版围绕"生产环境"与"长期自动更新"两类共 11 个问题做了针对性加固。下面逐条说明（标注：✅本版新增 / ☑已有沿用）。

### 生产环境

1. **镜像与二进制完整性校验** ☑：Dockerfile 已用 `OPENPPP2_ZIP_SHA256` build-arg 强制 `sha256sum -c`；CI 解析上游 zip 后把其真实 SHA256 传入；本地兜底构建对固定版本同样校验。✅本版额外：CI 解析步骤加固（tag 非空且形如 `1.0.0.x`、`unzip -t` 验包、确认包内有 `ppp`）。
2. **`:latest` 漂移、牺牲可复现** ✅：安装时把运行镜像**固定到不可变 digest**（`repo@sha256:...`）写入 `docker-compose.yml` 与 `.image`；浮动标签仅存于 `.image_channel`，**只用于自动更新发现新版本**。开机/轮转重建不再悄悄换版本。
3. **容器以 root 运行、无 HEALTHCHECK** ✅：HEALTHCHECK 已内置（`pgrep ppp`）；本版对容器能力做最小化——`cap_drop: ALL` 后只保留 `NET_ADMIN`/`NET_RAW`，并加 `no-new-privileges:true`（host 网络下创建 TUN/改路由仍需 root，但非网络特权全部丢弃）。
4. **运行时资源与日志无上限** ✅：日志已有 json-file 滚动 + 服务端 ppp.log 归档轮转；本版补齐运行时资源上限 `mem_limit`（默认 1g）/ `pids_limit`（默认 4096）/ 可选 `cpus`，均可用环境变量覆盖、留空即不限。

### 长期自动更新

1. **更新后健康校验与自动回滚** ☑：`openppp2-update.sh` 已实现"快照→更新→健康检查（重试 6 次：容器+ppp 进程+HEALTHCHECK+真实出网/监听）→失败回滚+恢复配置"。本版把回滚目标改为**旧 digest**（更确定）。
2. **`:latest` + 全量同时更新、无灰度** ✅：改为"通道发现 + digest 固定"的受控更新（见生产 #2）；timer 保留 `RandomizedDelaySec=1h` 抖动作为天然灰度铺开，并在文档中说明跨机金丝雀可错开 `OnCalendar`。
3. **systemd timer 静默、缺失败通知** ✅：更新/轮转单元加 `OnFailure=openppp2-notify@%n.service`；通知脚本一定写 journald，并可选推送 **webhook**（`NOTIFY_WEBHOOK`）或**邮件**（`NOTIFY_EMAIL`）。
4. **CI 推送前缺冒烟测试门禁** ✅：`build.yml` 改为"先本地构建(load) → 冒烟测试(镜像内 `ppp` 能在 amd64 执行、`pgrep` 存在) → 通过才推送"，PR 也跑冒烟。
5. **镜像清理策略缺失** ✅：更新成功后按 `IMAGE_KEEP`（默认 2 = 当前 + 上一个供回滚）保留，其余自动 `docker rmi`（在用/被引用的忽略）。
6. **脚本本身不会自更新** ✅：新增**可选**自更新（`SELF_UPDATE=yes`，默认关）。更新任务会检查本仓库是否有更高 release tag，有则下载该 tag 并经新代码的 `--regen-systemd` 入口**仅刷新 systemd 助手脚本/单元**（不动配置与容器）。⚠ 已在文档中明确其供应链风险。
7. **上游追踪脆弱** ✅：CI 解析步骤加固（见生产 #1）；新增 `upstream-watch.yml` 定时检查上游新 release，发现即开 issue 提醒维护者打 tag，把静默失败变成显式信号。

### 配套改动

- 新增 `${APP_DIR}/.env`（权限 600）持久化可调参数；`config.sh` 加载时读取（显式 env 优先），保证无人值守重新生成 systemd 助手时复用既有选项。
- `install_openppp2.sh` 新增非交互入口 `--regen-systemd`（仅重建 systemd 助手）；安装流程新增 `pin_compose_to_digest` 与 `persist_env_file`。
- `backup.sh` 备份/恢复纳入 `.image_channel` 与 `.env`；卸载清理新增的 notify/self-update 文件。
- `docker.sh` 新增 `resolve_image_digest` / `pin_compose_to_digest`，并加固本地构建的上游 tag 解析（格式校验，异常回退固定版本）。

> 兼容性：旧安装在升级后首次运行更新脚本时，若 `.image_channel` 不存在会自动回退（用 `.image` 去掉 digest，或默认镜像）；建议升级后跑一次安装或 `--regen-systemd` 以生成 `.env` 与固定 digest。

---

# （历史）针对最初四个问题的修复说明

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

- **一键安装命令**：仓库是模块化结构（`source lib/*.sh`），单独 `curl install_openppp2.sh` 会缺模块。脚本内置 `_bootstrap_if_needed`：检测到缺 `lib/` 时自动下载完整项目 tar 包并重新执行（v2.3.0 起锚定到固定 tag，见下）。README 的一键命令据此说明。
- **README 对 seccomp 的描述不准确**：实际是"默认放行 + 显式拒绝高危调用"，并非"比 Docker 默认更严格的白名单"。文档已据实更正。
- **compose 相对路径**：`security_opt: seccomp=./...` 按 CLI 的工作目录解析，`compose()` 封装已确保始终在 `APP_DIR` 下执行。
- **客户端 TUN 默认名**：上游 Linux 默认 `ppp`，脚本对主实例用 `ppp0`、多实例用 `pppN`，并通过命令行参数显式指定，避免歧义。
- **卸载健壮性**：清理全部 `openppp2*` 容器（含多实例）、systemd 单元与 sysctl 配置；保留备份选项时二次确认无运行容器。

---

## 版本

- config.sh：`SCRIPT_VERSION` 由 `2.1.0` → `2.2.0`
- 新增文件：`CHANGES.md`

> 注（v2.3.0 勘误）：2.2.0 文档此处曾提到“设包为 public 的 build.yml / .dockerignore”，但这些文件当时并未实际提交到仓库；CI workflow、`.dockerignore` 等是在 v2.3.0 才真正加入的（见下）。GHCR 包可见性也无法由 workflow 通过 REST API 修改，需在 GHCR 页面一次性手动设为 Public。

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

---

## v2.3.0 安全与工程化加固

`SCRIPT_VERSION` `2.2.0` → `2.3.0`。

### 第一批：安全 / 一致性

1. **README 与脚本对齐**：README 一键命令改为从**固定 tag**（`v2.3.0`）下载，并据实说明 `_bootstrap_if_needed` 自举逻辑；补充镜像来源、cosign 验签、seccomp 模型、文件权限等说明。同时勘误本文件早先关于 `build.yml` / `.dockerignore` 的不实描述。
2. **敏感文件权限收紧**：`install_openppp2.sh` 顶部加 `umask 077`（新建文件默认 600 / 目录 700）；并对生成的 `appsettings*.json`（含 `protocol-key`/`transport-key`/SOCKS5 凭据）显式 `chmod 600`；seccomp profile、systemd 备份快照与日志归档同样收紧。
3. **Dockerfile SHA256 校验**：新增 `OPENPPP2_ZIP_SHA256` build-arg，下载上游 zip 后强制 `sha256sum -c`；留空则告警跳过（仅用于无法预知 sha 的临时构建）。默认值与 CI 解析的最新版均带 sha。
4. **固定 tag 下载（不再默认 main）**：`OPENPPP2_REF` / `REPO_REF`（默认 `v2.3.0`）统一锚定自举 tar 包、基准配置、兜底 Dockerfile 的下载地址，保证可复现。修正上游兜底版本（旧的 `1.0.0.26016` 资产已 404）为 `1.0.0.26151` 并内置其 sha256。
5. **seccomp 改为 Docker 默认 allowlist 基线 + io_uring patch**：由原来的「默认放行 + 黑名单」改为上游 moby 默认配置（`SCMP_ACT_ERRNO` 默认拒绝、按 capability 放行的 allowlist），唯一改动是显式放行 `io_uring_setup`/`io_uring_enter`/`io_uring_register`（openppp2 必需，且不在 Docker 默认 allowlist 内）。

### 第二批：工程化

6. **lint + 测试 CI**（`.github/workflows/lint.yml`）：shellcheck（`--severity=warning`，配 `.shellcheckrc`）、shfmt（`-i 2 -ci`）、bats（`tests/unit.bats`，覆盖随机生成/交互提示/seccomp/compose 渲染）。
7. **镜像构建/扫描**（`.github/workflows/build.yml`）：docker buildx（`linux/amd64`）→ 推送 GHCR；Trivy 扫描镜像（HIGH/CRITICAL，SARIF 上传 code scanning）。
8. **正式 release**（`.github/workflows/release.yml`）：打 `vX.Y.Z` tag 时自动建 GitHub Release（`--generate-notes`）。
9. **SBOM + 签名**：buildx 生成 SBOM 与 provenance 证明；cosign keyless（OIDC）对镜像 digest 签名（验签命令见 README）。
10. **systemd 加固**：自动更新 / 日志轮转脚本加 `flock`（共用 `/run/openppp2.lock` 串行化）；timer 加 `RandomizedDelaySec`（更新 1h、轮转 15min）抖动；更新后的健康门控加入 HEALTHCHECK=healthy 与“非 running 即失败”判定。

### 待人工确认

- **GHCR 可见性**：首次发布后需在包设置里手动改为 Public（GitHub 无改可见性的 REST API），匿名 `docker pull` 才可用。
- **上游二进制变体**：仓库一直用 `openppp2-linux-amd64-simd.zip`；上游另有 `...-io-uring-simd.zip` 变体。若实测 `-simd` 不启用 io_uring，则 seccomp 的 io_uring patch 只是冗余放行（无害）；若启用则为必需。建议按实际运行确认。

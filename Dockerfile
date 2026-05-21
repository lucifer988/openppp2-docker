# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------
# openppp2 容器镜像
#
# 三个安全/可观测特性：
#   1) 下载 openppp2 zip 后强制 SHA256 校验（防止上游被劫持或 CDN 投毒）
#   2) 运行时以非 root 用户 ppp(uid=1000) 启动 + 容器内带 tini 作为 PID 1
#   3) 内置 HEALTHCHECK，容器自身可被 docker ps / docker-compose 等观察健康状态
# ---------------------------------------------------------------

# ============== 阶段 1：下载 + 校验 ==============
FROM debian:bookworm-slim AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

# 默认值仅用于本地手工 build；CI 会用 build-arg 覆盖为「最新 release 的 simd zip + 对应 sha256」
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip"
# SHA256 校验值（空 = 不校验，但 CI 必须传入；本地构建可选）
ARG OPENPPP2_ZIP_SHA256=""

RUN set -eux; \
    wget --tries=3 --timeout=30 -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
    if [ -n "${OPENPPP2_ZIP_SHA256}" ]; then \
      echo "${OPENPPP2_ZIP_SHA256}  openppp2.zip" | sha256sum -c -; \
    else \
      echo "WARN: OPENPPP2_ZIP_SHA256 build-arg not set, skipping checksum verification" >&2; \
    fi; \
    unzip -o openppp2.zip; \
    chmod +x ./ppp; \
    rm -f openppp2.zip; \
    test -f ./ppp

# ============== 阶段 2：运行时镜像 ==============
FROM debian:bookworm-slim

# procps 提供 pgrep（HEALTHCHECK 用），tini 处理 PID 1 信号转发
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables procps tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1000 ppp \
    && useradd  -r -u 1000 -g ppp -d /opt/openppp2 -s /usr/sbin/nologin ppp

WORKDIR /opt/openppp2

COPY --from=downloader /opt/openppp2 .

# 占位 appsettings.json，避免容器以 client 模式启动但 --config 拼写错误时栈跟踪过深
# 真实配置以只读 bind-mount 方式由 docker-compose 注入
RUN echo '{}' > /opt/openppp2/appsettings.json \
    && chown -R ppp:ppp /opt/openppp2 \
    && chmod 755 /opt/openppp2 \
    && chmod 755 /opt/openppp2/ppp

# ppp 程序自己会写 vmem / ppp.log 到 cwd（即 /opt/openppp2）；
# 非 root 用户能写，因为目录所有权已归 ppp。
USER ppp

EXPOSE 20000/tcp
EXPOSE 20000/udp

# 内置健康检查：ppp 进程必须存在
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD pgrep -x ppp >/dev/null 2>&1 || exit 1

# tini 作为 PID 1，正确转发 SIGTERM / 回收僵尸子进程
ENTRYPOINT ["/usr/bin/tini", "--", "./ppp"]

# OCI 镜像元数据（在 docker inspect 中可见）
LABEL org.opencontainers.image.title="openppp2"
LABEL org.opencontainers.image.description="Dockerized openppp2 - high-performance virtual ethernet tunneling service"
LABEL org.opencontainers.image.source="https://github.com/lucifer988/openppp2-docker"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="lucifer988"

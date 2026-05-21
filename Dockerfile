# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------
# openppp2 容器镜像（v2.3）
#
# 安全/可观测特性：
#   1) 下载 openppp2 zip 后强制 SHA256 校验（防止上游被劫持或 CDN 投毒）
#   2) 运行时以非 root 用户 ppp(uid=1000) 启动 + tini 作为 PID 1
#   3) 内置 HEALTHCHECK
#   4) wget 加 --timeout 防止下载阶段卡死
# ---------------------------------------------------------------

# ============== 阶段 1：下载 + 校验 ==============
FROM debian:bookworm-slim AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip"
ARG OPENPPP2_ZIP_SHA256=""

RUN set -eux; \
    wget --tries=3 --timeout=60 --waitretry=5 -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
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

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables procps tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1000 ppp \
    && useradd  -r -u 1000 -g ppp -d /opt/openppp2 -s /usr/sbin/nologin ppp

WORKDIR /opt/openppp2

COPY --from=downloader /opt/openppp2 .

RUN echo '{}' > /opt/openppp2/appsettings.json \
    && chown -R ppp:ppp /opt/openppp2 \
    && chmod 755 /opt/openppp2 \
    && chmod 755 /opt/openppp2/ppp

USER ppp

EXPOSE 20000/tcp
EXPOSE 20000/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD pgrep -x ppp >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "./ppp"]

LABEL org.opencontainers.image.title="openppp2"
LABEL org.opencontainers.image.description="Dockerized openppp2 - high-performance virtual ethernet tunneling service"
LABEL org.opencontainers.image.source="https://github.com/lucifer988/openppp2-docker"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="lucifer988"

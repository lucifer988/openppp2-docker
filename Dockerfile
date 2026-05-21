# syntax=docker/dockerfile:1.7
# openppp2-docker hotfix Dockerfile
# 默认使用当前确认可下载的 upstream release；也可 docker build 时通过 --build-arg OPENPPP2_ZIP_URL=... 覆盖。

FROM debian:bookworm-slim AS downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26151/openppp2-linux-amd64-simd.zip"
ARG OPENPPP2_ZIP_SHA256=""

RUN set -eux; \
    wget --tries=3 --timeout=60 --waitretry=5 -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
    if [ -n "${OPENPPP2_ZIP_SHA256}" ]; then \
      echo "${OPENPPP2_ZIP_SHA256}  openppp2.zip" | sha256sum -c -; \
    else \
      echo "WARN: OPENPPP2_ZIP_SHA256 not set, skipping checksum verification" >&2; \
    fi; \
    unzip -o openppp2.zip; \
    chmod +x ./ppp; \
    rm -f openppp2.zip; \
    test -f ./ppp

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables procps tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 1000 ppp \
    && useradd -r -u 1000 -g ppp -d /opt/openppp2 -s /usr/sbin/nologin ppp

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

LABEL org.opencontainers.image.title="openppp2-hotfix"
LABEL org.opencontainers.image.description="Dockerized openppp2 hotfix package"
LABEL org.opencontainers.image.source="https://github.com/lucifer988/openppp2-docker"

FROM debian:bookworm-slim AS downloader
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/openppp2
# 默认值固定指向一个已知可用的 release；CI 会用 build-arg 覆盖成"最新 release 的 simd zip"。
# OPENPPP2_ZIP_SHA256 为该 zip 的 SHA256：非空时强制校验（CI/复现构建必校验），
# 留空则跳过校验并打印告警（仅用于无法预知 sha 的临时构建，例如本机拉取"最新"时）。
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26151/openppp2-linux-amd64-simd.zip"
ARG OPENPPP2_ZIP_SHA256="8718483672c9cab36fedd3ebdb233600d967aba9452a074af6a8620473639d29"
RUN set -eux; \
    wget -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
    if [ -n "${OPENPPP2_ZIP_SHA256}" ]; then \
        echo "${OPENPPP2_ZIP_SHA256}  openppp2.zip" | sha256sum -c -; \
    else \
        echo "WARNING: OPENPPP2_ZIP_SHA256 为空，跳过完整性校验（不建议用于正式镜像）。" >&2; \
    fi; \
    unzip -o openppp2.zip; \
    chmod +x ./ppp; \
    rm -f openppp2.zip; \
    test -f ./ppp

FROM debian:bookworm-slim
# iproute2 提供 ip/ss；procps 提供 pgrep/pidof，HEALTHCHECK 与外层健康检查都会用到
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 iptables procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/openppp2
COPY --from=downloader /opt/openppp2 .
RUN echo '{}' > /opt/openppp2/appsettings.json

EXPOSE 20000/tcp
EXPOSE 20000/udp

# 健康检查：容器内必须有运行中的 ppp 进程，否则判定为 unhealthy
# （比"容器 Running"更接近"服务真的在跑"；端口/隧道连通性由外层脚本进一步探测）
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD pgrep -x ppp >/dev/null 2>&1 || exit 1

ENTRYPOINT ["./ppp"]

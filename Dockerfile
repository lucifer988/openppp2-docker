FROM debian:bookworm-slim AS downloader
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/openppp2
# 默认值仅用于本地手工 build；CI 会用 build-arg 覆盖成"最新 release 的 simd zip"
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip"
RUN set -eux; \
    wget -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
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

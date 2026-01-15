FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip iproute2 iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

# 默认固定到 1.0.0.26016 的 amd64 io-uring-simd（你要求的默认值）
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip"

RUN wget -O openppp2.zip "${OPENPPP2_ZIP_URL}" \
 && unzip openppp2.zip \
 && chmod +x ./ppp \
 && rm -f openppp2.zip \
 && test -f ./ppp

# 镜像里只放占位配置；生产环境用 volume 覆盖
RUN echo '{}' > /opt/openppp2/appsettings.json

EXPOSE 20000/tcp
EXPOSE 20000/udp

ENTRYPOINT ["./ppp"]

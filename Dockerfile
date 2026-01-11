FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip iproute2 iptables \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

# 你要求的默认值（amd64 io-uring-simd，且固定到 1.0.0.26016）
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-io-uring-simd.zip"

RUN wget -O openppp2.zip "${OPENPPP2_ZIP_URL}" \
  && unzip openppp2.zip \
  && chmod +x ./ppp \
  && rm -f openppp2.zip

# 镜像里放一个占位配置（实际运行时用 volume 覆盖）
COPY appsettings.json /opt/openppp2/appsettings.json

EXPOSE 20000
ENTRYPOINT ["./ppp"]

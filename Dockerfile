FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip iproute2 iptables \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

# 默认下载：amd64 + io-uring + simd（你指定的 URL）
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-io-uring-simd.zip"

RUN wget -O openppp2.zip "${OPENPPP2_ZIP_URL}" \
  && unzip openppp2.zip \
  && chmod +x ./ppp \
  && rm -f openppp2.zip

# 容器内默认读取 /opt/openppp2/appsettings.json
COPY appsettings.json /opt/openppp2/appsettings.json

EXPOSE 20000
ENTRYPOINT ["./ppp"]

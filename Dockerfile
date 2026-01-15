FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget unzip iproute2 iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2

# 默认值仅用于本地手工 build；CI 会用 build-arg 覆盖成“最新 release 的 simd zip”
ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/download/1.0.0.26016/openppp2-linux-amd64-simd.zip"

RUN set -eux; \
    wget -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
    unzip -o openppp2.zip; \
    chmod +x ./ppp; \
    rm -f openppp2.zip; \
    test -f ./ppp

RUN echo '{}' > /opt/openppp2/appsettings.json

EXPOSE 20000/tcp
EXPOSE 20000/udp

ENTRYPOINT ["./ppp"]

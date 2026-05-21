# syntax=docker/dockerfile:1.6
# =============================================================================
#  openppp2 — Docker image (multi-stage)
#  Upstream: https://github.com/liulilittle/openppp2
# =============================================================================

# ---------- Stage 1: downloader ----------
FROM debian:bookworm-slim AS downloader

ARG OPENPPP2_ZIP_URL="https://github.com/liulilittle/openppp2/releases/latest/download/openppp2-linux-amd64-simd.zip"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget unzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/openppp2
RUN set -eux; \
    wget -O openppp2.zip "${OPENPPP2_ZIP_URL}"; \
    unzip -o openppp2.zip; \
    chmod +x ./ppp; \
    rm -f openppp2.zip; \
    test -f ./ppp

# ---------- Stage 2: runtime ----------
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables \
 && rm -rf /var/lib/apt/lists/* \
 && update-ca-certificates

WORKDIR /opt/openppp2
COPY --from=downloader /opt/openppp2/ ./
RUN echo '{}' > /opt/openppp2/appsettings.json

EXPOSE 20000/tcp
EXPOSE 20000/udp

ENTRYPOINT ["./ppp"]

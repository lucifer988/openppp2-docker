#!/usr/bin/env bash
set -euo pipefail
echo "== OS =="
cat /etc/os-release || true
echo
echo "== APT Caddy sources =="
ls -l /etc/apt/sources.list.d/*caddy* 2>/dev/null || echo "no caddy source files"
echo
echo "== Docker =="
docker --version 2>/dev/null || true
docker compose version 2>/dev/null || true
docker-compose version 2>/dev/null || true
systemctl status docker --no-pager 2>/dev/null | sed -n '1,12p' || true
echo
echo "== /opt/openppp2 =="
ls -lah /opt/openppp2 2>/dev/null || true
file /opt/openppp2/appsettings.json 2>/dev/null || true
echo
echo "== Containers =="
docker ps -a --filter name=openppp2 2>/dev/null || true

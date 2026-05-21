#!/usr/bin/env bash
# openppp2 一键安装入口
# 本地运行：
#   sudo bash quick-install.sh
#
# GitHub 一键运行：
#   curl -fsSL https://raw.githubusercontent.com/你的用户名/你的仓库名/main/quick-install.sh | sudo bash
#
# 发布到 GitHub 前，把下面这行改成你的仓库：
GITHUB_REPO_DEFAULT="你的用户名/你的仓库名"

set -euo pipefail

APP_NAME="openppp2-docker-hotfix"
WORKDIR="/root/${APP_NAME}"
BRANCH="${BRANCH:-main}"
GITHUB_REPO="${GITHUB_REPO:-$GITHUB_REPO_DEFAULT}"

echo "=============================="
echo "  openppp2 一键安装"
echo "=============================="

# 情况 1：用户已经 clone 或解压了完整项目，直接运行本地安装脚本。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
if [[ -n "$SCRIPT_DIR" && -f "${SCRIPT_DIR}/install_openppp2.sh" ]]; then
  cd "$SCRIPT_DIR"
  chmod +x install_openppp2.sh
  exec ./install_openppp2.sh
fi

# 情况 2：通过 curl | bash 运行，需要从 GitHub 下载完整项目。
if [[ "$GITHUB_REPO" == "你的用户名/你的仓库名" ]]; then
  echo "[x] 还没有配置 GitHub 仓库地址。"
  echo
  echo "请先把 quick-install.sh 里的这一行："
  echo "  GITHUB_REPO_DEFAULT=\"你的用户名/你的仓库名\""
  echo
  echo "改成你的仓库，例如："
  echo "  GITHUB_REPO_DEFAULT=\"yourname/openppp2-docker-hotfix\""
  echo
  exit 1
fi

echo "[*] 正在下载项目：https://github.com/${GITHUB_REPO}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

TMP_TAR="/tmp/${APP_NAME}.tar.gz"
curl -fsSL "https://github.com/${GITHUB_REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$TMP_TAR"
tar -xzf "$TMP_TAR" -C "$WORKDIR" --strip-components=1

cd "$WORKDIR"
chmod +x install_openppp2.sh
exec ./install_openppp2.sh

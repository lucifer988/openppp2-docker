# openppp2-docker

一键脚本部署 openppp2（仅支持 amd64）。支持 Server / Client 双模式、同机多实例、自动更新与失败回滚。

## 安装

在 root（或 sudo）下，下载主脚本并运行即可。脚本会自动安装 Docker/Compose 及依赖，缺少模块时会自动拉取完整项目：

```bash
curl -fsSL https://raw.githubusercontent.com/lucifer988/openppp2-docker/main/install_openppp2.sh -o install_openppp2.sh
sudo bash install_openppp2.sh
```

运行后按菜单操作：

```
1) 安装 openppp2          # 选 1=服务端 / 2=客户端，按提示输入
2) 卸载 openppp2
3) 新增 openppp2 客户端实例
4) 查看客户端配置和代理信息
5) 删除客户端实例/配置
6) 备份当前配置文件
7) 回滚（恢复最新备份）
```

### 服务端

选择 `1` → `1`（服务端），输入公网 IP / 监听 IP。脚本会随机生成并打印 `kf` / `protocol-key` / `transport-key`（同时保存到 `/opt/openppp2/server-credentials.txt`），**客户端安装时需要这三项**。

### 客户端

选择 `1` → `2`（客户端），输入服务端 IP / 端口，并粘贴服务端的 `kf` / `protocol-key` / `transport-key`（必须完全一致）。脚本会随机生成本机 SOCKS5 用户名/密码并打印。

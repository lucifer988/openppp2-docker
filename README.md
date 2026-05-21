# openppp2-docker 一键安装版

这个项目是 `openppp2` 的 Docker 一键部署脚本。

已修复这些常见问题：

- Caddy 源 `NO_PUBKEY ABA1F9B8875A6661`
- `appsettings.json: Is a directory`
- `docker compose: No such file or directory`
- openppp2 旧版本下载地址 `404`
- 容器启动时报 `cannot start a stopped process`

---

## 一键安装

### 方式一：下载压缩包后安装

```bash
cd /root
tar -xzf openppp2-docker-hotfix-2.3.3-simple.tar.gz
cd openppp2-docker-hotfix-2.3.3-simple
sudo bash quick-install.sh
```

然后按提示选择：

```text
1) 安装 openppp2
1) 服务端（Server）
```

一路回车即可。

---

## 上传到 GitHub 后的一键命令

上传到你自己的 GitHub 仓库后，先改一下 `quick-install.sh` 里的这一行：

```bash
GITHUB_REPO_DEFAULT="你的用户名/你的仓库名"
```

例如你的仓库是：

```text
https://github.com/abc/openppp2-docker-hotfix
```

就改成：

```bash
GITHUB_REPO_DEFAULT="abc/openppp2-docker-hotfix"
```

以后别人只需要执行：

```bash
curl -fsSL https://raw.githubusercontent.com/abc/openppp2-docker-hotfix/main/quick-install.sh | sudo bash
```

---

## 服务端安装成功后

查看容器：

```bash
cd /opt/openppp2
sudo docker compose ps
```

查看日志：

```bash
sudo docker logs openppp2 --tail=100
```

你的服务端默认端口是：

```text
20000/tcp
20000/udp
```

---

## 卸载

```bash
cd /root/openppp2-docker-hotfix-2.3.3-simple
sudo bash quick-install.sh
```

然后选择：

```text
2) 卸载 openppp2
```

---

## 常用命令

重启：

```bash
cd /opt/openppp2
sudo docker compose restart
```

停止：

```bash
cd /opt/openppp2
sudo docker compose down
```

重新启动：

```bash
cd /opt/openppp2
sudo docker compose up -d --force-recreate
```

查看日志：

```bash
sudo docker logs openppp2 -f
```

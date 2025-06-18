# PVE-LXC-NAT 网页管理器

一个简单的Web应用程序，用于通过网页界面管理 `iptables` NAT 转发规则，尤其适用于在 Proxmox VE (PVE) 等环境下的 Linux 主机。

## 功能

* **添加端口转发**: 轻松添加 DNAT 规则，将主机端口映射到内部IP和端口。
* **查看规则**: 清晰地列出当前 `nat` 表 `PREROUTING` 链中的所有规则。
* **删除规则**: 根据行号快速删除指定的转发规则。
* **保存与加载**:
    * 将当前 NAT 表的规则保存到文件 (`/etc/iptables/rules.v4`)，以便持久化。
    * 从文件加载规则，此操作会覆盖当前的 NAT 表。
* **清空链**: 一键清空 `PREROUTING` 链中的所有规则。

## 环境要求

* Linux 操作系统 (推荐 Debian/Ubuntu)
* Python 3 和 pip
* `iptables`
* `sudo` 或 `root` 权限

## 快速部署

#### 1. 上传文件

将 `app.py` 文件和 `templates` 整个文件夹上传到您的服务器，例如 `/opt/nat-web/` 目录。

#### 2. 安装依赖

```bash
pip3 install Flask Flask-WTF gunicorn
```

#### 3. 运行应用

**重要**:
* 运行前，请使用 `ip a` 命令确定您的 **公网网卡名称** (例如 `eth0`, `enp7s0`)。
* 此应用需要 `root` 权限来执行 `iptables` 命令。

使用 `gunicorn` 启动应用 (推荐方式):

```bash
# cd 到你的应用目录
cd /opt/nat-web/

# 使用 sudo 启动应用，并替换你的网卡名和密钥
sudo PUBLIC_INTERFACE=enp7s0 SECRET_KEY='在这里设置一个长而随机的安全密钥' gunicorn --workers 1 --bind 0.0.0.0:5000 app:app
```

#### 4. 访问

部署成功后，在浏览器中打开 `http://<你的服务器IP>:5000` 即可开始使用。

## 规则持久化 (推荐)

为了让服务器重启后 `iptables` 规则不丢失，建议安装 `iptables-persistent`。

```bash
# 以 Debian/Ubuntu 为例
sudo apt-get update
sudo apt-get install -y iptables-persistent
```

安装过程中会提示是否保存当前规则，选择“是”即可。之后，在Web界面中点击 **“保存规则到文件”**，规则就会被 `iptables-persistent` 服务记录，实现开机自动加载。

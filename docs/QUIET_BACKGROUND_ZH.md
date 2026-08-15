# Windows 低打扰后台记录与服务器同步

## 新电脑直接运行（无需 Python）

仓库中的 `portable/CatchMe.exe` 是便携式单文件程序，不是安装包。克隆仓库后直接运行：

```powershell
git clone https://github.com/YacgoSomaz/CatchMe.git
& '.\CatchMe\portable\CatchMe.exe'
```

首次运行会弹出 Windows 授权窗口。只有点击“是”后，程序才会保存授权、创建当前用户登录
启动项并立即进入托盘后台。点击“否”不会启动记录或创建启动项。克隆目录需要保留在原位。

若 Agent 需要在首次运行时配置服务器，可仅在该进程环境中提供
`CATCHME_SERVER_URL` 与 `CATCHME_SYNC_TOKEN`；程序会把令牌写入 Windows 凭据管理器，
随后从进程环境中删除它。不要把真实令牌提交到仓库。

该模式用于个人设备：安装时确认一次采集范围，之后随 Windows 登录在后台启动。运行时不打开终端、不发送日常弹窗，通过系统托盘图标提供暂停、立即同步、打开数据目录和退出入口。

## 默认采集范围

- 活动窗口上下文；
- 应用最终接收的文本和快捷键；
- 不超过 1 MiB 的文本剪贴板；
- 活跃/空闲状态。

截图、鼠标轨迹和通知默认关闭。UI Automation 标记为密码控件的输入不会读取；密码管理器和配置的敏感窗口会在写入 SQLite 前排除。常见 API Key、JWT 和私钥会在保存前替换为脱敏标记。

## 一条安装命令

```powershell
git clone https://github.com/YacgoSomaz/CatchMe.git
cd CatchMe
.\install.ps1
```

安装脚本会创建仓库内的 `.venv`、安装项目、显示一次采集授权说明，然后创建普通的 Windows 用户启动项并立即启动托盘进程。不需要管理员权限。

如果服务器 HTTPS 地址已经准备好：

```powershell
.\install.ps1 -ServerUrl https://memory.example.com
```

同步令牌会通过隐藏输入读取，并保存在 Windows Credential Manager；不会写入 `config.json`。

## 常用命令

```powershell
.\.venv\Scripts\catchme.exe consent status
.\.venv\Scripts\catchme.exe startup status
.\.venv\Scripts\catchme.exe sync now
.\.venv\Scripts\catchme.exe sync disable
.\.venv\Scripts\catchme.exe startup remove
.\.venv\Scripts\catchme.exe consent revoke
```

撤销授权会删除授权文件和 Windows 启动项。若托盘进程正在运行，应从托盘菜单选择 `Exit CatchMe`。

## 服务器接收器

参考接收器提供：

- `POST /v1/events/batches`：接收 gzip 批次；
- `GET /v1/events/export?date=YYYY-MM-DD`：按 UTC 日期导出；
- Bearer Token 验证；
- 基于 `event_id` 的幂等去重。

推荐通过 Docker Compose 启动 Gunicorn 接收器：

```bash
export CATCHME_SERVER_TOKEN='replace-with-a-long-random-token'
docker compose -f docker-compose.server.yml up -d
```

Compose 默认只把端口发布到服务器的 `127.0.0.1:8780`，应由 Nginx、Caddy
或其他反向代理提供 HTTPS。客户端拒绝明文 HTTP。`catchme receive` 使用 Flask
内置服务器，只适合本机调试，不应直接用于生产部署。

导出示例：

```bash
curl -H "Authorization: Bearer $CATCHME_SERVER_TOKEN" \
  "http://127.0.0.1:8780/v1/events/export?date=2026-08-14"
```

参考接收器使用服务器端 SQLite，数据本身未做数据库字段加密；生产部署应使用加密磁盘、严格文件权限、备份加密和访问审计。服务器日志不会打印事件正文或令牌。

## 配置

配置位于 `~/.catchme/config.json`。关键段落：

```json
{
  "capture": {
    "enabled_recorders": ["window", "keyboard", "clipboard", "idle"],
    "clipboard_max_bytes": 1048576,
    "redact_secrets": true,
    "excluded_apps": ["1password", "bitwarden", "keepass", "keepassxc"],
    "excluded_window_titles": ["password", "密码", "验证码"]
  },
  "sync": {
    "enabled": true,
    "server_url": "https://memory.example.com",
    "interval_seconds": 60,
    "batch_size": 250,
    "timeout_seconds": 20
  }
}
```

`clipboard_max_bytes` 即使配置为更大的数字，也会被客户端强制限制到 1 MiB。

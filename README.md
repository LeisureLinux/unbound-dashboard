# Unbound DNS Dashboard

轻量级 **[Unbound](https://github.com/NLnetLabs/unbound) DNS 实时可视化看板**，用 Go 编写，SQLite 存储。支持从 Unbound verbose-log 或 DNSTap socket 读取数据，提供 Top10 查询域名 / 拦截域名的仪表盘界面。

```
端口 : 9153
前端 : 内嵌 HTML（单文件部署）
后端 : REST API (JSON) + SQLite
数据源 : Unbound verbose-log 文件或 DNSTap Unix Socket
```

---

## 快速开始

```bash
# 1. 克隆
git clone https://github.com/LeisureLinux/adhole.git
cd adhole/utils/unbound-dashboard

# 2. 安装依赖
go mod download

# 3. 编译 (本机 amd64)
CGO_ENABLED=1 go build -ldflags="-s -w" -o bins/unbound-dashboard ./cmd/

# 4. 运行（必须指定数据源）
./unbound-dashboard --dnstap /var/lib/unbound/dnstap.sock
# 或
./unbound-dashboard --log-file /var/log/unbound-debug.log
```

访问 `http://<server>:9153` 即可看到仪表盘。

---

## Unbound 配置

### 模式一：DNSTap 模式（推荐）

**优点**：实时流式传输，性能更好，结构化数据

在 `/etc/unbound/unbound.conf` 中添加：

```yaml
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: "/var/lib/unbound/dnstap.sock"
    
    # 客户端流量（下游查询和响应）
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
    
    # 可选：递归迭代流量（出站到权威 DNS）
    # dnstap-log-resolver-query-messages: yes
    # dnstap-log-resolver-response-messages: yes
    
    # 可选：转发流量（出站到上游转发器）
    # dnstap-log-forwarder-query-messages: yes
    # dnstap-log-forwarder-response-messages: yes
```

**注意**：
- Unbound 必须编译时启用 dnstap 支持（`--enable-dnstap`）
- 检查方法：`unbound -V 2>&1 | grep -i dnstap`
- Socket 文件由 Unbound 自动创建，dashboard 作为客户端连接

启动 dashboard：
```bash
./unbound-dashboard --dnstap /var/lib/unbound/dnstap.sock
```

### 模式二：日志文件模式

**优点**：兼容性好，无需额外编译选项

1. 在 `/etc/unbound/unbound.conf` 中启用 verbose logging：

```yaml
server:
    verbosity: 2
    log-time-ascii: yes
    log-queries: yes
    log-replies: yes
    log-servfail: yes
```

2. 配置 rsyslog 将 unbound 日志输出到独立文件：

```bash
# /etc/rsyslog.d/unbound.conf
:programname, isequal, "unbound" /var/log/unbound-debug.log
& stop
```

3. 重启服务：
```bash
sudo systemctl restart rsyslog
sudo systemctl restart unbound
```

启动 dashboard：
```bash
./unbound-dashboard --log-file /var/log/unbound-debug.log
```

---

## 交叉编译：ARM64 (树莓派 / NanoPC 等)

### 前置条件：安装交叉编译工具链

在 **x86_64 开发机**上执行：

```bash
sudo apt update
sudo apt install gcc-aarch64-linux-gnu golang-go -y
```

确认工具链就绪：

```bash
which aarch64-linux-gnu-gcc    # 必须输出路径
aarch64-linux-gnu-gcc --version
```

### 交叉编译命令

```bash
cd /path/to/unbound-dashboard

GOOS=linux GOARCH=arm64 \
CGO_ENABLED=1 \
CC=aarch64-linux-gnu-gcc \
CXX=aarch64-linux-gnu-g++ \
go build -ldflags="-s -w" -o bins/unbound-dashboard-arm64 ./cmd/
```

编译参数说明：
- `-ldflags="-s -w"`：strip 调试信息，减小二进制体积（约 12M → 7M）

### 验证产物

```bash
file bins/unbound-dashboard-arm64
# 应输出: ELF 64-bit LSB executable, ARM aarch64 ...

scp bins/unbound-dashboard-arm64 user@raspberry-pi:/usr/local/bin/unbound-dashboard
```

---

## 配置参数

| 短参数 | 长参数 | 默认值 | 说明 |
|--------|--------|--------|------|
| `-a` | `--addr` | `127.0.0.1` | HTTP 监听地址 |
| `-p` | `--port` | `9153` | HTTP 监听端口 |
| `-d` | `--data-dir` | `/var/lib/unbound` | SQLite 数据库存放目录 |
| `-D` | `--dnstap` | _(空)_ | DNSTap socket 路径（与 -l 二选一） |
| `-l` | `--log-file` | _(空)_ | DNS Server Log file path（与 -D 二选一） |
| `-t` | `--ttl` | `90` | 数据保留天数（数据库存储） |
| `-S` | `--size` | `200` | 数据库最大大小（MB，最大 9999） |
| `-V` | `--version` | - | 显示版本号 |
| `-h` | `--help` | - | 显示帮助信息 |

**注意**：
- 必须指定 `-D/--dnstap` 或 `-l/--log-file` 之一，否则程序会报错退出
- 短参数（单横杠）和长参数（双横杠）等价，如 `-V` = `--version`
- 数据默认保留 90 天，可通过 `-t/--ttl` 参数调整
- 数据库默认最大 200MB，可通过 `-S/--size` 参数调整（最大 9999MB）
- 程序每小时自动清理过期数据，并检查数据库大小

---

## API 接口

启动后提供三个 HTTP 端点（端口默认 9153）：

| 路径 | 格式 | 说明 |
|------|------|------|
| `/` | HTML | 可视化仪表盘，5 秒自动刷新 |
| `/stats` | JSON | 统计数据，适合脚本/监控集成 |
| `/debug` | Text | 运行时调试信息（数据源、数据库路径、最近 5 条记录） |

### /stats 示例

```bash
curl -s http://localhost:9153/stats | jq
```

返回：

```json
{
  "total_queries": 12345,
  "blocked_queries": 678,
  "uptime": "3h25m10s",
  "top_queries": [
    {"Name": "example.com", "Value": 523},
    {"Name": "dns.google", "Value": 412}
  ],
  "top_blocked": [
    {"Name": "ads.tracker.com", "Value": 89},
    {"Name": "telemetry.evil.com", "Value": 67}
  ]
}
```

### /debug 示例

```bash
curl http://localhost:9153/debug
```

返回纯文本：

```
== Unbound Dashboard Debug Info ==

Data Source Type : DNSTap Socket
Connection Path  : /var/lib/unbound/dnstap.sock
Storage Location : /var/lib/unbound/dashboard.db

--- Statistics ---
Total Queries    : 12345
Blocked Queries  : 678

--- Last 5 Records Ingested ---
  [NOERROR] example.com (A) -> 93.184.216.34
  [NXDOMAIN] blocked.ads (A) -> NXDOMAIN
```

## Systemd 服务（推荐）

### DNSTap 模式

```ini
# /etc/systemd/system/unbound-dashboard.service
[Unit]
Description=Unbound DNS Dashboard
Documentation=https://github.com/LeisureLinux/unbound-dashboard/
After=network.target unbound.service
Wants=unbound.service

[Service]
Type=simple
ExecStart=/usr/local/bin/unbound-dashboard \
    --dnstap /var/lib/unbound/dnstap.sock \
    --data-dir /var/lib/unbound
Restart=always
RestartSec=5
User=root
Group=root

# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/unbound
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### 日志文件模式

```ini
# /etc/systemd/system/unbound-dashboard.service
[Unit]
Description=Unbound DNS Dashboard
Documentation=https://github.com/LeisureLinux/unbound-dashboard/
After=network.target unbound.service

[Service]
Type=simple
ExecStart=/usr/local/bin/unbound-dashboard \
    --log-file /var/log/unbound-debug.log \
    --data-dir /var/lib/unbound
Restart=always
RestartSec=5
User=root
Group=root

# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/unbound
ReadOnlyPaths=/var/log/unbound-debug.log
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### 启用服务

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now unbound-dashboard
sudo systemctl status unbound-dashboard
```

---

## 项目结构

```
unbound-dashboard/
├── cmd/main.go          # 入口：启动 HTTP server + ingestor goroutine
├── core/types.go        # Config / QueryRecord 类型定义
├── database/
│   └── database.go      # SQLite CRUD + Top-N 聚合查询
├── api/
│   └── handlers.go      # HTTP handler：/stats, /debug, / (HTML dashboard)
├── ingestor/
│   ├── base.go          # Parser 接口 + LogReader 实现
│   └── dnstap.go        # DNSTap Frame Streams 协议实现
└── build.sh             # 自动版本号 + 交叉编译脚本
```

---

## 版本历史

- **v0.2.33** 拦截数显示百分比，默认数据目录改为 /var/lib/unbound
- **v0.2.31** 无参数启动报错退出，--help 显示 GitHub 地址
- **v0.2.30** 添加 --version 参数，--help 自定义帮助信息
- **v0.2.29** 界面右上角添加 GitHub/B站/Twitter 图标，去掉时钟
- **v0.2.28** 清理调试日志，优化 Frame Streams 双向握手
- **v0.2.20** 实现 DNSTap Frame Streams 协议，支持 protobuf 解析
- **v0.2** 修复拦截图表为空问题，拦截/查询图表位置互换
- **v0.1** 添加去重机制，修复 ingestor 循环语法错误

---

## License

MIT

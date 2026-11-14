# Unbound DNS Dashboard

轻量级 **[Unbound](https://github.com/NLnetLabs/unbound) DNS 实时可视化看板**，用 Go 编写，SQLite 存储。单二进制部署，支持从 Unbound 的 [DNSTap](https://dnstap.info/) socket 或 verbose-log 读取数据，提供 Top10 查询域名 / 拦截域名的仪表盘界面。

```
端口 : 9153（默认只监听 127.0.0.1）
前端 : 内嵌 HTML（单文件部署）
后端 : REST API (JSON) + Prometheus /metrics + SQLite
数据源 : DNSTap Unix Socket 或 Unbound verbose log
```

与 [DNS-collector](https://github.com/dmachard/DNS-collector) 的定位不同：它是通用的 DNS 遥测**管道**（多种 collector → transformer → logger），需要 YAML 配置和外部数据栈；本项目是一个**开箱即用的本地看板**。本项目借鉴了它的边缘处理（normalize / traffic filtering / user privacy）、批处理与 `*_traffic_total` 指标思路，但没有引入 Kafka/ClickHouse/Loki/Grafana 之类的外部依赖。

---

## 安装

### 方式一：Freelamp APT 仓库（推荐）

```bash
curl -fsSL https://repo.freelamp.com/apt.key | sudo gpg --dearmor -o /usr/share/keyrings/freelamp.gpg
sudo tee /etc/apt/sources.list.d/freelamp.sources >/dev/null <<'EOF'
Types: deb
URIs: https://repo.freelamp.com
Suites: bookworm
Components: main
Signed-By: /usr/share/keyrings/freelamp.gpg
EOF
sudo apt update
sudo apt install unbound-dashboard
```

### 方式二：源码编译

```bash
git clone https://github.com/LeisureLinux/unbound-dashboard.git
cd unbound-dashboard
go mod download
./build.sh                 # 自动生成 amd64 + arm64，版本取自 git tag

# 或手动构建
CGO_ENABLED=1 go build -ldflags="-s -w -X main.Version=$(git describe --tags --always)" \
    -o bins/unbound-dashboard ./cmd/
```

运行前先验证配置：

```bash
./bins/unbound-dashboard --test-config --dnstap /var/lib/unbound/dnstap.sock
./bins/unbound-dashboard --dnstap /var/lib/unbound/dnstap.sock
```

访问 `http://127.0.0.1:9153`。

---

## Unbound 配置

### 模式一：DNSTap（推荐）

```yaml
# /etc/unbound/unbound.conf
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: "/var/lib/unbound/dnstap.sock"
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes
```

> Unbound 需启用 `--enable-dnstap`（`unbound -V | grep -i dnstap` 检查）。
> **dashboard 是服务端**，创建并监听该 socket；Unbound 作为客户端连入。
> socket 默认权限 `0660`、属组 `unbound`，可用 `-m` / `-g` 调整。

```bash
./unbound-dashboard --dnstap /var/lib/unbound/dnstap.sock
```

DNSTap 会为一次查询产生 **query + response 两个帧**，本程序用 LRU 关联器合并成一条记录，并计算真实延迟；默认只接收 `CLIENT_QUERY,CLIENT_RESPONSE`（可用 `--dnstap-types` 打开递归/转发流量）。

### 模式二：verbose log

```yaml
server:
    verbosity: 2
    log-time-ascii: yes
    log-queries: yes
    log-replies: yes
```

```bash
# /etc/rsyslog.d/unbound.conf
:programname, isequal, "unbound" /var/log/unbound-debug.log
& stop
```

```bash
./unbound-dashboard --log-file /var/log/unbound-debug.log
```

tailer 会按 inode 检测 logrotate（rename + create），并只推进到最后一个完整换行，不会吞掉半行；历史数据使用日志里的时间戳而不是启动时间。

---

## 配置参数

| 短 | 长 | 默认 | 说明 |
|----|----|------|------|
| `-D` | `--dnstap PATH` | — | DNSTap socket 路径（与 `-l` 二选一） |
| `-l` | `--log-file PATH` | — | Unbound verbose log（与 `-D` 二选一） |
| `-a` | `--addr ADDR` | `127.0.0.1` | HTTP 监听地址 |
| `-p` | `--port PORT` | `9153` | HTTP 监听端口 |
| `-d` | `--data-dir DIR` | `/var/lib/unbound` | SQLite 目录 |
| `-t` | `--ttl DAYS` | `90` | 数据保留天数 |
| `-S` | `--size MB` | `200` | 数据库上限（超过后分批淘汰最旧记录） |

**边缘处理（借鉴 DNS-collector 的 transformers）：**

| 短 | 长 | 默认 | 说明 |
|----|----|------|------|
| `-i` | `--ignore-domains LIST` | 空 | 逗号分隔的域名后缀，命中即在入库前丢弃（去健康检查噪声） |
| `-b` | `--block-rcodes LIST` | `NXDOMAIN,REFUSED` | 计入"拦截/异常"的响应码；设为空则只认 RPZ/policy 信号 |
| `-y` | `--dnstap-types LIST` | `CLIENT_QUERY,CLIENT_RESPONSE` | 允许进入关联器的 DNSTap 消息类型 |
| `-A` | `--anonymize-ip` | off | 用带随机盐的 SHA256 哈希客户端 IP 后再存储（GDPR） |
| `-r` | `--log-from-start` | on | 启动时读取整个日志文件；用 `--log-from-start=false` 只跟新数据 |

**DNSTap socket 与写入器：**

| 短 | 长 | 默认 | 说明 |
|----|----|------|------|
| `-m` | `--socket-mode OCTAL` | `0660` | socket 权限（不再是 `0777`） |
| `-g` | `--socket-group NAME` | `unbound` | socket 属组；设为空跳过 chown |
| `-q` | `--queue-size N` | `4096` | 摄入队列容量，满时丢帧并计入 `records_dropped_total` |
| `-B` | `--batch-size N` | `64` | 每个 SQLite 事务的记录数 |
| `-f` | `--flush-ms N` | `10` | 未满批次的最大刷新延迟 |

**其他：**

| 短 | 长 | 说明 |
|----|----|------|
| `-P` | `--debug-public` | 允许非 loopback 访问 `/debug`（默认拒绝） |
| `-k` | `--debug-token TOKEN` | `/debug` 需要 `Authorization: Bearer <token>` |
| `-T` | `--test-config` | 只校验配置并退出（对应 DNS-collector 的 `-test-config`） |
| `-V` | `--version` | 显示版本（由 `-ldflags -X main.Version` 注入） |
| `-h` | `--help` | 帮助 |

短参数与长参数等价，`--addr=0.0.0.0` / `--dnstap=/path` 也都支持。

---

## API

| 路径 | 格式 | 说明 |
|------|------|------|
| `/` | HTML | 仪表盘，5 秒刷新；所有域名/Host 均做 HTML 转义 |
| `/stats` | JSON | 统计数据（小写 JSON 字段） |
| `/metrics` | text | Prometheus 文本格式，见下表 |
| `/healthz` | JSON | 存活检查 |
| `/debug` | text | 数据源、路径、最近 5 条、管道计数器；默认仅 loopback |

`/stats` 示例：

```json
{
  "version": "v0.3.0",
  "total_queries": 12345,
  "blocked_queries": 678,
  "uptime": "3h25m10s",
  "since": "2026-11-01 08:12:33",
  "top_queries": [{"name": "example.com", "value": 523}],
  "top_blocked": [{"name": "ads.tracker.com", "value": 89}],
  "rcode_breakdown": [{"name": "NOERROR", "value": 11000}]
}
```

`/metrics` 主要指标（对应 DNS-collector 的 `worker_ingress/egress/discarded_traffic_total`）：

```
unbound_dashboard_frames_received_total
unbound_dashboard_frames_parsed_total
unbound_dashboard_frames_malformed_total
unbound_dashboard_records_enqueued_total
unbound_dashboard_records_dropped_total
unbound_dashboard_records_inserted_total
unbound_dashboard_records_ignored_total
unbound_dashboard_insert_errors_total
unbound_dashboard_batches_flushed_total
unbound_dashboard_connections_total / disconnects_total / log_rotations_total
```

> `records_dropped_total > 0` 说明 SQLite 跟不上，应调大 `--batch-size` /
> `--queue-size`，或把数据目录放到更快的磁盘上。

---

## Systemd

```ini
[Unit]
Description=Unbound DNS Dashboard
After=network.target unbound.service
Wants=unbound.service

[Service]
Type=simple
ExecStart=/usr/local/bin/unbound-dashboard \
    --dnstap /var/lib/unbound/dnstap.sock \
    --data-dir /var/lib/unbound \
    --socket-group unbound
Restart=always
RestartSec=5
User=unbound-dashboard
Group=unbound

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/unbound
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

> 程序不再需要 `root`。若用专用用户，确保 `/var/lib/unbound` 可写、且
> socket 目录允许该用户创建 socket；`-g unbound` 让 Unbound 能连入。

---

## v0.3.0 修复清单

参照 DNS-collector 的工程实践，本版本处理了以下问题：

| 问题 | 处理 |
|------|------|
| 图表 CSS 写成 `width:50%%`，所有进度条零宽 | 单 `%`，并有回归测试 |
| 域名 / `Host` 未转义导致存储型 XSS | `html.EscapeString` + 测试 |
| `UNIQUE(client_ip,domain,qtype,timestamp)` + 整数秒时间戳 → 同一秒重复查询被 `INSERT OR IGNORE` 吞掉 | 去掉 UNIQUE，自动迁移旧库，引入 `count` 权重列 |
| 每帧一次 `db.Exec`（无事务/无 prepared stmt） | channel + 批量事务写入，带背压计数 |
| DNSTap 只解析 DNS 报文，丢弃 envelope | 解析 identity / client IP / wire 时间戳 / rcode / answers / EDNS / policy |
| query 与 response 各算一次查询 | LRU 关联器合并为一条，计算延迟，超时查询也会落库 |
| 收到 STOP 后 `Start()` 返回 nil，Unbound 重启后看板静默冻结 | 连接 goroutine 化、持续 Accept、摄入错误升级为致命 |
| `os.Remove(任意路径)` + `0777` socket | 只删真正的陈旧 socket、拨号探测、`0660` + 属组 |
| 无帧长上限 / 无超时 / 压缩指针死循环 | 64KB 帧上限、握手 5s / 读 30s 超时、最多 32 次指针跳转 |
| logrotate 后继续读旧 inode、半行被吞、历史用 `time.Now()` | inode 检测 + 重开、只消费完整行、解析日志时间戳 |
| "blocked" 口径混乱（NXDOMAIN 既算又注释说不算） | `--block-rcodes` 显式策略 + 单独的 `rcode_breakdown` + RPZ policy 信号 |
| `--addr=1.2.3.4` 静默失效 | 长短参数同时注册，支持 `=` 语法 |
| 版本号硬编码在源码、tag 与二进制可能不一致 | `-ldflags -X main.Version`，release workflow 注入 tag |
| 无测试、无 CI、gofmt 不干净 | 7 个包的单测（含端到端 fstrm 测试）+ `ci.yml`（gofmt/vet/race/coverage/govulncheck），release 依赖 CI |
| `/debug` 无鉴权且暴露路径与最近域名 | 默认仅 loopback，可选 bearer token |
| README 指向旧仓库 `adhole/utils/...`、缺 LICENSE | 修正并补齐 |

---

## 项目结构

```
unbound-dashboard/
├── cmd/main.go                     # 入口：配置校验、启动 HTTP + ingestor + writer
├── core/
│   ├── types.go                    # Config / QueryRecord / 参数校验
│   └── helpers.go                  # normalize / filter / privacy / 指标 / Sink
├── database/database.go            # SQLite 迁移 + 批量事务写入 + 聚合查询
├── api/handlers.go                 # / /stats /metrics /healthz /debug
├── ingestor/
│   ├── edge.go                     # 入库前的 normalize → filter → privacy
│   ├── merger.go                   # query/response LRU 关联器
│   ├── dnstap.go                   # fstrm 服务端（并发、超时、帧长上限）
│   ├── dnstap_decode.go            # dnstap.Dnstap protobuf 解码
│   ├── base.go                     # inode 感知的日志 tailer
│   ├── protobuf/                   # 零依赖、带边界检查的 protobuf 子集
│   └── dnspacket/                  # 带边界检查的 DNS 报文解析
├── build.sh                        # amd64 + arm64，版本来自 git tag
├── packaging/                      # .deb / systemd / maintainer scripts
└── .github/workflows/{ci,release}.yml
```

---

## License

MIT — 见 [LICENSE](LICENSE)。

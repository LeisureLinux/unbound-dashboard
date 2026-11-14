// Package api provides the dashboard HTML, JSON stats, health and metrics.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"time"

	"unbound-dashboard/core"
	"unbound-dashboard/database"
)

type Handler struct {
	db      *database.Database
	cfg     *core.Config
	version string
}

var startTime = time.Now()

func NewHandler(db *database.Database, cfg *core.Config, version string) *Handler {
	return &Handler{db: db, cfg: cfg, version: version}
}

/* ================================================================== */
/*  /stats                                                             */
/* ================================================================== */

func (h *Handler) HandleStats(w http.ResponseWriter, r *http.Request) {
	total := h.db.GetTotalQueries()
	blocked := h.db.GetBlockedQueries()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":         h.version,
		"total_queries":   total,
		"blocked_queries": blocked,
		"uptime":          time.Since(startTime).Truncate(time.Second).String(),
		"since":           h.db.GetOldestTimestamp(),
		"top_queries":     h.db.TopQueries(10),
		"top_blocked":     h.db.RejectedQueries(10),
		"rcode_breakdown": h.db.RCodeStats(),
	})
}

/* ================================================================== */
/*  / — dashboard                                                      */
/* ================================================================== */

const cssStyle = `
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;background:#f5f6fa;color:#2d3436}
.container{max-width:1100px;margin:0 auto;padding:20px}
header{display:flex;justify-content:space-between;align-items:center;background:#fff;padding:24px;border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,.06);margin-bottom:24px}
.card{background:#fff;padding:24px;border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,.06);margin-bottom:24px}
h1{margin:0;font-size:1.6em;color:#2d3436}
h3{margin-top:0;font-size:1.15em;color:#636e72}
.row{display:flex;gap:20px;margin-bottom:24px}
.stat-box{flex:1;text-align:center;padding:20px;border:1px solid #dfe6e9;border-radius:12px;background:#fafafa}
.stat-val{font-size:2.4em;font-weight:700;color:#2d3436}
.stat-label{color:#b2bec3;margin-top:4px;font-size:.95em}
.chart-row{display:flex;align-items:center;margin-bottom:8px;font-size:.9em}
.chart-row .label{width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#636e72}
.chart-row .bar-wrap{flex:1;height:22px;background:#eee;border-radius:6px;overflow:hidden;margin:0 10px}
.chart-row .bar{height:100%;border-radius:6px;transition:width .4s ease}
.blue{background:linear-gradient(90deg,#0984e3,#74b9ff)}
.red{background:linear-gradient(90deg,#d63031,#ff7675)}
.muted{color:#b2bec3}
footer{text-align:center;color:#b2bec3;font-size:.85em;padding:8px 0 24px}
</style>
`

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	total := h.db.GetTotalQueries()
	blocked := h.db.GetBlockedQueries()
	blockedPct := 0.0
	if total > 0 {
		blockedPct = float64(blocked) / float64(total) * 100
	}
	host := html.EscapeString(r.Host)
	if host == "" {
		host = "localhost"
	}
	since := html.EscapeString(h.db.GetOldestTimestamp())
	if since == "" {
		since = "—"
	}

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unbound DNS Dashboard</title>`)
	b.WriteString(cssStyle)
	b.WriteString(`</head>
<body>
<div class="container">
<header>
<div><h1>🌲 Unbound DNS Dashboard</h1><small>Real-time visualization · Powered by Go</small><br><small>Since: ` + since + `</small></div>
<div style="text-align:right">
<small>Instance: ` + host + `</small>
<div style="margin-top:8px">
<a href="https://github.com/LeisureLinux/unbound-dashboard/" target="_blank" rel="noopener" style="margin-right:12px;text-decoration:none;color:#333">GitHub</a>
<a href="https://space.bilibili.com/517298151" target="_blank" rel="noopener" style="margin-right:12px;text-decoration:none;color:#00a1d6">Bilibili</a>
<a href="https://x.com/zenboy999" target="_blank" rel="noopener" style="text-decoration:none;color:#000">X</a>
</div>
</div>
</header>

<div class="row">
<div class="stat-box"><div class="stat-val">` + fmt.Sprintf("%d", total) + `</div><div class="stat-label">总查询数</div></div>
<div class="stat-box"><div class="stat-val" style="color:#d63031">` + fmt.Sprintf("%d", blocked) + ` <small style="font-size:0.6em;opacity:0.8">(` + fmt.Sprintf("%.1f", blockedPct) + `%)</small></div><div class="stat-label">拦截/异常</div></div>
</div>
`)

	b.WriteString(`<div class="card"><h3>Top 10 拦截/异常域名</h3>`)
	renderBars(&b, h.db.RejectedQueries(10), "red")
	b.WriteString(`</div>`)

	b.WriteString(`<div class="card"><h3>Top 10 查询域名</h3>`)
	renderBars(&b, h.db.TopQueries(10), "blue")
	b.WriteString(`</div>`)

	b.WriteString(`<div class="card"><h3>响应码分布</h3>`)
	renderBars(&b, h.db.RCodeStats(), "blue")
	b.WriteString(`<p class="muted" style="margin-top:12px;font-size:.85em">NXDOMAIN 是正常的否定应答，不等于拦截；可通过 <code>--block-rcodes</code> 调整口径。</p></div>`)

	b.WriteString(`<footer>` + html.EscapeString(h.version) + ` · <a href="/stats">/stats</a> · <a href="/metrics">/metrics</a> · <a href="/healthz">/healthz</a></footer>
</div>
<script>setInterval(()=>location.reload(),5000);</script>
</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprint(w, b.String())
}

// renderBars escapes every untrusted label. The old code both injected raw
// domain names (stored XSS) and wrote a literal "%%" into the inline style,
// which made every bar zero-width.
func renderBars(b *strings.Builder, items []database.StatItem, cls string) {
	maxV := int64(0)
	for _, it := range items {
		if it.Value > maxV {
			maxV = it.Value
		}
	}
	if maxV == 0 {
		b.WriteString(`<p class="muted">暂无数据</p>`)
		return
	}
	for _, it := range items {
		width := int(float64(it.Value) / float64(maxV) * 100)
		if width < 1 {
			width = 1
		}
		name := html.EscapeString(it.Name)
		b.WriteString(`<div class="chart-row"><span class="label" title="`)
		b.WriteString(name)
		b.WriteString(`">`)
		b.WriteString(name)
		b.WriteString(`</span><div class="bar-wrap"><div class="bar ` + cls + `" style="width:`)
		b.WriteString(fmt.Sprintf("%d", width))
		b.WriteString(`%"></div></div><span class="val">`)
		b.WriteString(fmt.Sprintf("%d", it.Value))
		b.WriteString(`</span></div>`)
	}
}

/* ================================================================== */
/*  /metrics, /healthz, /debug                                         */
/* ================================================================== */

func (h *Handler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	core.RenderPrometheus(w)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok", "version": h.version,
		"uptime": time.Since(startTime).Truncate(time.Second).String(),
	})
}

// isLoopback reports whether the request came from the local machine.
func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HandleDebug exposes paths and the last queried domains. It is restricted
// to loopback unless --debug-public is set explicitly.
func (h *Handler) HandleDebug(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.DebugPublic && !isLoopback(r) {
		http.Error(w, "403 /debug is loopback-only (use --debug-public to override)", http.StatusForbidden)
		return
	}
	if h.cfg.DebugToken != "" {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		token := []byte(strings.TrimPrefix(auth, prefix))
		want := []byte(h.cfg.DebugToken)
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare(token, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="unbound-dashboard debug"`)
			http.Error(w, "401 unauthorized", http.StatusUnauthorized)
			return
		}
	}
	sourceType, dsn := "unknown", "none"
	switch {
	case h.cfg.DNSTapPath != "":
		sourceType, dsn = "DNSTap Socket", h.cfg.DNSTapPath
	case h.cfg.LogFilePath != "":
		sourceType, dsn = "Log File", h.cfg.LogFilePath
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "== Unbound Dashboard Debug Info ==\n\n")
	fmt.Fprintf(w, "Version          : %s\n", h.version)
	fmt.Fprintf(w, "Data Source Type : %s\n", sourceType)
	fmt.Fprintf(w, "Connection Path  : %s\n", dsn)
	fmt.Fprintf(w, "Storage Location : %s/dashboard.db\n", h.cfg.DataDir)
	fmt.Fprintf(w, "Block RCodes     : %s\n", h.cfg.BlockRCodes)
	fmt.Fprintf(w, "Anonymize IP     : %v\n", h.cfg.AnonymizeIP)
	fmt.Fprintf(w, "\n--- Statistics ---\n")
	fmt.Fprintf(w, "Total Queries    : %d\n", h.db.GetTotalQueries())
	fmt.Fprintf(w, "Blocked Queries  : %d\n", h.db.GetBlockedQueries())
	fmt.Fprintf(w, "\n--- Pipeline Counters ---\n")
	core.RenderPrometheus(w)
	fmt.Fprintf(w, "\n--- Last 5 Records Ingested ---\n")
	records := h.db.RecentRecords(5)
	if len(records) == 0 {
		fmt.Fprintln(w, "  (No records found in database yet)")
	}
	for _, rec := range records {
		fmt.Fprintf(w, "  %s\n", rec)
	}
}

func (h *Handler) GetRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", h.HandleStats)
	mux.HandleFunc("/metrics", h.HandleMetrics)
	mux.HandleFunc("/healthz", h.HandleHealth)
	mux.HandleFunc("/debug", h.HandleDebug)
	mux.HandleFunc("/", h.handleIndex)
	return mux
}

// Package api provides RESTful JSON endpoints.
package api

import (
	"fmt"
	"net/http"
	"encoding/json"
	"strings"
	"time"

	"unbound-dashboard/core"
	"unbound-dashboard/database"
)

type Handler struct {
	db  *database.Database
	cfg *core.Config
}

var startTime = time.Now()

func NewHandler(db *database.Database, cfg *core.Config) *Handler {
	return &Handler{db: db, cfg: cfg}
}

/* ================================================================== */
/*  /stats API                                                         */
/* ================================================================== */
func (h *Handler) HandleStats(w http.ResponseWriter, r *http.Request) {
	total := h.db.GetTotalQueries()
	blocked := h.db.GetBlockedQueries()
	topQ := h.db.TopQueries(10)
	topB := h.db.RejectedQueries(10)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_queries":   total,
		"blocked_queries": blocked,
		"uptime":          time.Since(startTime).Truncate(time.Second).String(),
		"top_queries":     topQ,
		"top_blocked":     topB,
	})
}

/* ================================================================== */
/*  / — Dashboard Landing Page                                         */
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
</style>
`

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	total := h.db.GetTotalQueries()
	blocked := h.db.GetBlockedQueries()
	host := r.Host
	if host == "" { host = "localhost" }

	topQItems := h.db.TopQueries(10)
	topBItems := h.db.RejectedQueries(10)
	since := h.db.GetOldestTimestamp()

	// 计算拦截百分比
	var blockedPct float64
	if total > 0 {
		blockedPct = float64(blocked) / float64(total) * 100
	}

	// Build HTML using Buffer to safely handle formatting
	var buf strings.Builder
	
	buf.WriteString(`<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>Unbound DNS Dashboard</title>`)
	buf.WriteString(cssStyle)
	buf.WriteString(`</head>
<body>
<div class="container">
<header>
<div><h1>🌲 Unbound DNS Dashboard</h1><small>Real-time visualization · Powered by Go</small><br><small>Since: ` + since + `</small></div>
<div style="text-align:right">
<small>Instance: ` + host + `</small>
<div style="margin-top:8px">
<a href="https://github.com/LeisureLinux/unbound-dashboard/" target="_blank" style="margin-right:12px;text-decoration:none;color:#333">
<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
</a>
<a href="https://space.bilibili.com/517298151" target="_blank" style="margin-right:12px;text-decoration:none;color:#00a1d6">
<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M17.813 4.653h.854c1.51.054 2.769.578 3.773 1.574 1.004.995 1.524 2.249 1.56 3.76v7.36c-.036 1.51-.556 2.769-1.56 3.773s-2.262 1.524-3.773 1.56H5.333c-1.51-.036-2.769-.556-3.773-1.56S.036 18.859 0 17.347v-7.36c.036-1.511.556-2.765 1.56-3.76 1.004-.996 2.262-1.52 3.773-1.574h.774l-1.174-1.12a1.234 1.234 0 0 1-.373-.906c0-.356.124-.658.373-.907l.027-.027c.267-.249.573-.373.92-.373.347 0 .653.124.92.373L9.653 4.44c.071.071.134.142.187.213h4.267a.836.836 0 0 1 .16-.213l2.853-2.747c.267-.249.573-.373.92-.373.347 0 .662.151.929.4.267.249.391.551.391.907 0 .355-.124.657-.373.906zM5.333 7.24c-.746.018-1.373.276-1.88.773-.506.498-.769 1.13-.786 1.894v7.52c.017.764.28 1.395.786 1.893.507.498 1.134.756 1.88.773h13.334c.746-.017 1.373-.275 1.88-.773.506-.498.769-1.129.786-1.893v-7.52c-.017-.765-.28-1.396-.786-1.894-.507-.497-1.134-.755-1.88-.773zM8 11.107c.373 0 .684.124.933.373.25.249.383.569.4.96v1.173c-.017.391-.15.711-.4.96-.249.25-.56.374-.933.374s-.684-.125-.933-.374c-.25-.249-.383-.569-.4-.96V12.44c.017-.391.15-.711.4-.96.249-.249.56-.373.933-.373zm8 0c.373 0 .684.124.933.373.25.249.383.569.4.96v1.173c-.017.391-.15.711-.4.96-.249.25-.56.374-.933.374s-.684-.125-.933-.374c-.25-.249-.383-.569-.4-.96V12.44c.017-.391.15-.711.4-.96.249-.249.56-.373.933-.373z"/></svg>
</a>
<a href="https://x.com/zenboy999" target="_blank" style="text-decoration:none;color:#000">
<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
</a>
</div>
</div>
</header>

<div class="row">
<div class="stat-box"><div class="stat-val">` + fmt.Sprintf("%d", total) + `</div><div class="stat-label">总查询数</div></div>
<div class="stat-box"><div class="stat-val" style="color:#d63031">` + fmt.Sprintf("%d", blocked) + ` <small style="font-size:0.6em;opacity:0.8">(` + fmt.Sprintf("%.1f", blockedPct) + `%)</small></div><div class="stat-label">拦截/拒绝</div></div>
</div>

<div class="card">
<h3>Top 10 拦截域名</h3>
`)
	renderBarsToBuf(&buf, topBItems, "red")

	buf.WriteString(`</div>

<div class="card">
<h3>Top 10 查询域名</h3>
`)
	renderBarsToBuf(&buf, topQItems, "blue")

	buf.WriteString(`</div>
</div>
<script>setInterval(()=>location.reload(),5000);</script>
</body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, buf.String())
}

func (h *Handler) GetRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", h.HandleStats)
	mux.HandleFunc("/debug", h.HandleDebug)
	mux.HandleFunc("/", h.handleIndex)
	return mux
}

// renderBarsToBuf renders chart bars into the buffer safely
func renderBarsToBuf(buf *strings.Builder, items []database.StatItem, cls string) {
	maxV := maxVal(items)
	if maxV == 0 {
		buf.WriteString(`<p style="color:#b2bec3">暂无数据</p>`)
		return
	}
	for _, it := range items {
		width := int(float64(it.Value) / float64(maxV) * 100)
		buf.WriteString(`<div class="chart-row"><span class="label" title="`)
		buf.WriteString(it.Name)
		buf.WriteString(`">`)
		buf.WriteString(it.Name)
		buf.WriteString(`</span><div class="bar-wrap"><div class="bar ` + cls + `" style="width:`)
		buf.WriteString(fmt.Sprintf("%d", width))
		buf.WriteString(`%%"></div></div><span class="val">`)
		buf.WriteString(fmt.Sprintf("%d", it.Value))
		buf.WriteString(`</span></div>`)
	}
}

func maxVal(items []database.StatItem) int64 {
	var m int64
	for _, it := range items { if it.Value > m { m = it.Value } }
	return m
}


// HandleDebug provides runtime debugging information including DB connection details.
func (h *Handler) HandleDebug(w http.ResponseWriter, r *http.Request) {
	dataDir := h.cfg.DataDir
	
	sourceType := "unknown"
	dsn := "none"
	if h.cfg.DNSTapPath != "" {
		sourceType = "DNSTap Socket"
		dsn = h.cfg.DNSTapPath
	} else if h.cfg.LogFilePath != "" {
		sourceType = "Log File"
		dsn = h.cfg.LogFilePath
	} else {
		sourceType = "In-Memory/Default"
		dsn = dataDir + "/dashboard.db"
	}

	total := h.db.GetTotalQueries()
	blocked := h.db.GetBlockedQueries()
	
	rows, err := h.db.GetConn().Query("SELECT domain, qtype, rcode, response FROM query_log ORDER BY id DESC LIMIT 5")
	var lastRecords []string
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d, qt, rc, res string
			if err := rows.Scan(&d, &qt, &rc, &res); err == nil {
				lastRecords = append(lastRecords, fmt.Sprintf("[%s] %s (%s) -> %s", rc, d, qt, res))
			}
		}
	}
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "== Unbound Dashboard Debug Info ==\n\n")
	fmt.Fprintf(w, "Data Source Type : %s\n", sourceType)
	fmt.Fprintf(w, "Connection Path  : %s\n", dsn)
	fmt.Fprintf(w, "Storage Location : %s/dashboard.db\n", dataDir)
	fmt.Fprintf(w, "\n--- Statistics ---\n")
	fmt.Fprintf(w, "Total Queries    : %d\n", total)
	fmt.Fprintf(w, "Blocked Queries  : %d\n", blocked)
	fmt.Fprintf(w, "\n--- Last 5 Records Ingested ---\n")
	if len(lastRecords) > 0 {
		for _, rec := range lastRecords {
			fmt.Fprintf(w, "  %s\n", rec)
		}
	} else {
		fmt.Fprintln(w, "  (No records found in database yet)")
	}
}

// Package core provides type definitions, configuration and shared helpers.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

/* ================================================================== */
/*  Edge normalization (borrowed from DNS-collector's normalize,      */
/*  user-privacy and traffic-filtering transformers)                   */
/* ================================================================== */

// NormalizeDomain lowercases and strips the trailing root label. Doing this
// before GROUP BY prevents "Example.COM." and "example.com" becoming two
// separate Top-N entries.
func NormalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// IsAnomalousRCode reports whether an rcode deserves attention. NXDOMAIN is
// a *normal negative answer*, not a block; SERVFAIL/FORMERR/NOTIMP/REFUSED
// are anomalies. Whether they are counted as "blocked" is a separate,
// user-configurable policy (see ParseBlockRCodes).
func IsAnomalousRCode(rcode string) bool {
	switch strings.ToUpper(strings.TrimSpace(rcode)) {
	case "", "NOERROR", "NXDOMAIN":
		return false
	default:
		return true
	}
}

// ParseBlockRCodes turns a comma separated list into an uppercase set.
// An empty string means "no rcode counts as blocked" (only explicit policy
// signals, e.g. RPZ, do). The default is NXDOMAIN,REFUSED so the dashboard
// keeps its historical meaning; set "" to switch to strict semantics.
func ParseBlockRCodes(spec string) (map[string]bool, error) {
	set := make(map[string]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.ToUpper(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		switch part {
		case "NOERROR", "NXDOMAIN", "SERVFAIL", "FORMERR", "NOTIMP", "REFUSED":
		default:
			return nil, fmt.Errorf("unknown rcode %q in --block-rcodes", part)
		}
		set[part] = true
	}
	return set, nil
}

// BlockedByPolicy reports whether a record should be counted as blocked.
func BlockedByPolicy(rec QueryRecord, codes map[string]bool) (bool, string) {
	if rec.BlockReason != "" {
		return true, rec.BlockReason
	}
	rcode := strings.ToUpper(rec.RCode)
	if codes[rcode] {
		if rcode == "NXDOMAIN" {
			return true, "NXDOMAIN (negative answer)"
		}
		return true, rcode
	}
	return false, ""
}

// DomainFilter is a small allow/deny transformer: drop noise (health checks,
// internal probes) before it ever reaches SQLite.
type DomainFilter struct {
	suffixes []string
}

func NewDomainFilter(spec string) *DomainFilter {
	f := &DomainFilter{}
	for _, s := range strings.Split(spec, ",") {
		s = NormalizeDomain(s)
		for len(s) > 0 && s[0] == '.' {
			s = s[1:]
		}
		if s != "" {
			f.suffixes = append(f.suffixes, s)
		}
	}
	return f
}

func (f *DomainFilter) Ignored(domain string) bool {
	d := NormalizeDomain(domain)
	for _, s := range f.suffixes {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}

// Anonymizer implements DNS-collector's "user-privacy" idea with a keyed
// hash. A random per-process salt means stored IPs cannot be reversed by a
// dictionary attack, and they rotate on restart.
type Anonymizer struct {
	salt []byte
}

func NewAnonymizer() *Anonymizer {
	salt := make([]byte, 16)
	if f, err := os.Open("/dev/urandom"); err == nil {
		_, _ = f.Read(salt)
		_ = f.Close()
	}
	return &Anonymizer{salt: salt}
}

func (a *Anonymizer) IP(ip string) string {
	if a == nil || ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed != nil {
		ip = parsed.String()
	}
	sum := sha256.Sum256(append(a.salt, []byte(ip)...))
	return "anon-" + hex.EncodeToString(sum[:8])
}

/* ================================================================== */
/*  Metrics: DNS-collector's ingress/egress/discarded traffic totals */
/* ================================================================== */

// PipelineCounters mirrors DNS-collector's ingress/egress/discarded traffic
// totals. Fields are exported so ingestors and the writer can bump them.
type PipelineCounters struct {
	FramesReceived  atomic.Uint64
	FramesParsed    atomic.Uint64
	FramesMalformed atomic.Uint64
	RecordsEnqueued atomic.Uint64
	RecordsDropped  atomic.Uint64
	RecordsInserted atomic.Uint64
	RecordsIgnored  atomic.Uint64
	InsertErrors    atomic.Uint64
	BatchesFlushed  atomic.Uint64
	Connects        atomic.Uint64
	Disconnects     atomic.Uint64
	LogRotations    atomic.Uint64
}

// Metrics is the process-wide counter set. Kept dependency-free (no
// prometheus client library) so the project stays a single static binary.
var Metrics PipelineCounters

type metricDef struct {
	name string
	help string
	get  func() uint64
}

func metricDefs() []metricDef {
	return []metricDef{
		{"frames_received_total", "DNSTap data frames received", Metrics.FramesReceived.Load},
		{"frames_parsed_total", "DNSTap frames decoded into records", Metrics.FramesParsed.Load},
		{"frames_malformed_total", "Frames rejected as malformed or oversized", Metrics.FramesMalformed.Load},
		{"records_enqueued_total", "Records handed to the batched writer", Metrics.RecordsEnqueued.Load},
		{"records_dropped_total", "Records dropped because the ingest queue was full", Metrics.RecordsDropped.Load},
		{"records_inserted_total", "Records committed to SQLite", Metrics.RecordsInserted.Load},
		{"records_ignored_total", "Records removed by the domain filter", Metrics.RecordsIgnored.Load},
		{"insert_errors_total", "SQLite insert/transaction errors", Metrics.InsertErrors.Load},
		{"batches_flushed_total", "SQLite transactions committed", Metrics.BatchesFlushed.Load},
		{"connections_total", "DNSTap client connections accepted", Metrics.Connects.Load},
		{"disconnects_total", "DNSTap client connections closed", Metrics.Disconnects.Load},
		{"log_rotations_total", "Log file rotations detected by the tailer", Metrics.LogRotations.Load},
	}
}

// RenderPrometheus writes /metrics in the Prometheus text exposition format.
func RenderPrometheus(w interface{ Write([]byte) (int, error) }) {
	var b strings.Builder
	for _, m := range metricDefs() {
		fmt.Fprintf(&b, "# HELP unbound_dashboard_%s %s\n", m.name, m.help)
		fmt.Fprintf(&b, "# TYPE unbound_dashboard_%s counter\n", m.name)
		fmt.Fprintf(&b, "unbound_dashboard_%s %d\n", m.name, m.get())
	}
	_, _ = w.Write([]byte(b.String()))
}

/* ================================================================== */
/*  Sink: the seam between ingestors and the batched writer            */
/* ================================================================== */

// Sink receives records from an ingestor.
type Sink interface {
	Enqueue(rec QueryRecord)
}

// FuncSink adapts a function to Sink; handy for tests.
type FuncSink struct{ Fn func(QueryRecord) }

func (f FuncSink) Enqueue(rec QueryRecord) { f.Fn(rec) }

// CollectSink is a thread-safe Sink for tests and small tools.
type CollectSink struct {
	mu    sync.Mutex
	items []QueryRecord
}

func (c *CollectSink) Enqueue(rec QueryRecord) {
	c.mu.Lock()
	c.items = append(c.items, rec)
	c.mu.Unlock()
}

// Snapshot returns a copy of the collected records.
func (c *CollectSink) Snapshot() []QueryRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]QueryRecord(nil), c.items...)
}

// Len returns the number of collected records.
func (c *CollectSink) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

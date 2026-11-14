// Package core provides type definitions, configuration and shared helpers.
package core

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds application-wide settings.
//
// Every option is registered under both a short and a long name so that
// "-a 0.0.0.0", "--addr 0.0.0.0" and "--addr=0.0.0.0" all work. Go's flag
// package already accepts one or two leading dashes; the old preprocessor in
// main() rewrote "--word" by hand and silently broke "--word=value".
type Config struct {
	ListenAddr   string // HTTP listener address
	Port         int    // HTTP listen port
	DataDir      string // SQLite data directory path
	DNSTapPath   string // DNSTap unix socket path
	LogFilePath  string // Unbound verbose log file path
	CacheTTLDays int    // Data retention days
	MaxSizeMB    int    // Max database size in MB

	// DNSTap socket hardening.
	SocketModeStr string // octal, e.g. "0660"
	SocketMode    os.FileMode
	SocketGroup   string // optional group to chown the socket to

	// Lightweight versions of DNS-collector's "traffic filtering" and
	// "user privacy" transformers, applied at the edge before anything is
	// written to SQLite.
	IgnoreDomains string // comma separated suffixes to drop
	AnonymizeIP   bool   // hash client IPs before storage
	BlockRCodes   string // comma separated rcodes that count as blocked
	DNSTapTypes   string // comma separated DNSTap message types to ingest
	LogFromStart  bool   // read the whole log file at startup (default true)
	DebugPublic   bool   // allow /debug from non-loopback clients
	DebugToken    string // optional bearer token for /debug

	// Batched writer tuning (same shape as global.worker in DNS-collector).
	QueueSize int
	BatchSize int
	FlushMS   int

	TestConfig  bool // validate configuration and exit (like -test-config)
	VersionFlag bool // --version
}

// StringOpt registers one string option under two names.
func StringOpt(p *string, short, long, def, usage string) {
	flag.StringVar(p, short, def, usage)
	flag.StringVar(p, long, def, usage)
}

// IntOpt registers one int option under two names.
func IntOpt(p *int, short, long string, def int, usage string) {
	flag.IntVar(p, short, def, usage)
	flag.IntVar(p, long, def, usage)
}

// BoolOpt registers one bool option under two names.
func BoolOpt(p *bool, short, long string, def bool, usage string) {
	flag.BoolVar(p, short, def, usage)
	flag.BoolVar(p, long, def, usage)
}

// LoadConfig parses command line flags and returns a config instance.
// It performs no I/O: validation and directory creation happen in main so
// that --test-config stays side-effect free.
func LoadConfig() *Config {
	cfg := &Config{
		ListenAddr:    "127.0.0.1",
		Port:          9153,
		DataDir:       "/var/lib/unbound",
		CacheTTLDays:  90,
		MaxSizeMB:     200,
		SocketModeStr: "0660",
		SocketGroup:   "unbound",
		BlockRCodes:   "NXDOMAIN,REFUSED",
		DNSTapTypes:   "CLIENT_QUERY,CLIENT_RESPONSE",
		LogFromStart:  true,
		QueueSize:     4096,
		BatchSize:     64,
		FlushMS:       10,
	}

	StringOpt(&cfg.ListenAddr, "a", "addr", cfg.ListenAddr, "HTTP listen address")
	IntOpt(&cfg.Port, "p", "port", cfg.Port, "HTTP listen port")
	StringOpt(&cfg.DataDir, "d", "data-dir", cfg.DataDir, "Directory for database storage")
	StringOpt(&cfg.DNSTapPath, "D", "dnstap", "", "DNSTap unix socket path")
	StringOpt(&cfg.LogFilePath, "l", "log-file", "", "Unbound verbose log file path")
	IntOpt(&cfg.CacheTTLDays, "t", "ttl", cfg.CacheTTLDays, "Days to keep logs")
	IntOpt(&cfg.MaxSizeMB, "S", "size", cfg.MaxSizeMB, "Max database size in MB")

	StringOpt(&cfg.SocketModeStr, "m", "socket-mode", cfg.SocketModeStr, "DNSTap socket permissions (octal)")
	StringOpt(&cfg.SocketGroup, "g", "socket-group", cfg.SocketGroup, "Group to chown the DNSTap socket to (empty = keep)")
	StringOpt(&cfg.IgnoreDomains, "i", "ignore-domains", "", "Comma separated domain suffixes to drop before storage")
	BoolOpt(&cfg.AnonymizeIP, "A", "anonymize-ip", false, "Hash client IPs before storing them")
	StringOpt(&cfg.BlockRCodes, "b", "block-rcodes", cfg.BlockRCodes, "Comma separated rcodes counted as blocked")
	StringOpt(&cfg.DNSTapTypes, "y", "dnstap-types", cfg.DNSTapTypes, "DNSTap message types to ingest")
	BoolOpt(&cfg.LogFromStart, "r", "log-from-start", cfg.LogFromStart, "Read the whole log file at startup")
	BoolOpt(&cfg.DebugPublic, "P", "debug-public", false, "Allow /debug from non-loopback clients")
	StringOpt(&cfg.DebugToken, "k", "debug-token", "", "Require Authorization: Bearer <token> for /debug")

	IntOpt(&cfg.QueueSize, "q", "queue-size", cfg.QueueSize, "Ingest queue capacity (records)")
	IntOpt(&cfg.BatchSize, "B", "batch-size", cfg.BatchSize, "Records per SQLite transaction")
	IntOpt(&cfg.FlushMS, "f", "flush-ms", cfg.FlushMS, "Max delay before flushing a partial batch")

	BoolOpt(&cfg.TestConfig, "T", "test-config", false, "Validate configuration and exit")
	BoolOpt(&cfg.VersionFlag, "V", "version", false, "Show version and exit")

	flag.Parse()
	return cfg
}

// Validate checks the configuration and derives computed fields.
func (c *Config) Validate() error {
	if c.DNSTapPath != "" && c.LogFilePath != "" {
		return errors.New("--dnstap and --log-file are mutually exclusive")
	}
	if c.DNSTapPath == "" && c.LogFilePath == "" {
		return errors.New("a data source is required (--dnstap or --log-file)")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d (expected 1..65535)", c.Port)
	}
	if c.CacheTTLDays < 1 || c.CacheTTLDays > 9999 {
		return fmt.Errorf("invalid ttl %d (expected 1..9999)", c.CacheTTLDays)
	}
	if c.MaxSizeMB < 1 || c.MaxSizeMB > 9999 {
		return fmt.Errorf("invalid size %d (expected 1..9999)", c.MaxSizeMB)
	}
	if c.QueueSize < 1 || c.QueueSize > 1<<20 {
		return fmt.Errorf("invalid queue-size %d", c.QueueSize)
	}
	if c.BatchSize < 1 || c.BatchSize > 4096 {
		return fmt.Errorf("invalid batch-size %d", c.BatchSize)
	}
	if c.FlushMS < 1 || c.FlushMS > 1000 {
		return fmt.Errorf("invalid flush-ms %d", c.FlushMS)
	}

	mode, err := strconv.ParseUint(strings.TrimPrefix(c.SocketModeStr, "0o"), 8, 32)
	if err != nil || mode > 0o777 {
		return fmt.Errorf("invalid socket-mode %q (expected octal, e.g. 0660)", c.SocketModeStr)
	}
	c.SocketMode = os.FileMode(mode)

	if _, err := ParseBlockRCodes(c.BlockRCodes); err != nil {
		return err
	}
	if err := ingestorTypes(c.DNSTapTypes); err != nil {
		return err
	}
	return nil
}

// ingestorTypes is a tiny structural validation; the authoritative parser
// lives in the ingestor package (avoids an import cycle from core).
func ingestorTypes(spec string) error {
	valid := map[string]bool{
		"AUTH_QUERY": true, "AUTH_RESPONSE": true,
		"RESOLVER_QUERY": true, "RESOLVER_RESPONSE": true,
		"CLIENT_QUERY": true, "CLIENT_RESPONSE": true,
		"FORWARDER_QUERY": true, "FORWARDER_RESPONSE": true,
		"STUB_QUERY": true, "STUB_RESPONSE": true,
		"TOOL_QUERY": true, "TOOL_RESPONSE": true,
		"UPDATE_QUERY": true, "UPDATE_RESPONSE": true,
	}
	seen := false
	for _, s := range strings.Split(spec, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !valid[s] {
			return fmt.Errorf("unknown DNSTap message type %q", s)
		}
		seen = true
	}
	if !seen {
		return errors.New("--dnstap-types must not be empty")
	}
	return nil
}

// QueryRecord represents one DNS transaction, not one DNSTap frame.
// DNSTap emits a query frame *and* a response frame for the same lookup;
// the correlator merges them into a single record.
type QueryRecord struct {
	Timestamp    float64 // Unix epoch seconds, fractional
	ClientIP     string  // Client IP address (possibly anonymized)
	Domain       string  // Queried domain name, lowercased, no trailing dot
	QType        string  // Query type (A, AAAA, CNAME...)
	Response     string  // First A/AAAA answer, or ""
	RCode        string  // Response code (NOERROR, NXDOMAIN...)
	CacheHit     bool    // Was resolved from cache
	Blocked      bool    // Was blocked / refused
	BlockReason  string  // Reason for blocking
	DNSSECStatus string  // DNSSEC status
	Operation    string  // DNSTap message type, e.g. CLIENT_RESPONSE
	Identity     string  // DNSTap identity of the resolver
	LatencyMS    float64 // Response time - query time
	Count        int64   // Aggregation weight (always 1 from ingestors)
}

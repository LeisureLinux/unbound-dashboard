// Package core provides type definitions and configuration management.
package core

import (
	"flag"
	"fmt"
	"os"
)

// Config holds application-wide settings.
type Config struct {
	ListenAddr   string // HTTP listener address
	Port         int    // HTTP listen port (default 9153)
	DataDir      string // SQLite data directory path
	DNSTapPath   string // DNSTap socket/file path
	LogFilePath  string // Fallback unbound log file path
	CacheTTLDays int    // Data retention days
	MaxSizeMB    int    // Max database size in MB
}

// QueryRecord represents a parsed DNS query event.
type QueryRecord struct {
	Timestamp    float64 // Unix epoch seconds
	ClientIP     string  // Client IP address
	Domain       string  // Queried domain name
	QType        string  // Query type (A, AAAA, CNAME...)
	Response     string  // Parsed response
	RCode        string  // Response code (NOERROR, NXDOMAIN...)
	CacheHit     bool    // Was resolved from cache
	Blocked      bool    // Was blocked
	BlockReason  string  // Reason for blocking
	DNSSECStatus string  // DNSSEC status
}

// LoadConfig parses command line flags and returns a config instance.
func LoadConfig() *Config {
	cfg := &Config{
		ListenAddr:   "127.0.0.1",
		Port:         9153,
		DataDir:      "/var/lib/unbound",
		CacheTTLDays: 90,
		MaxSizeMB:    200,
	}

	// 单字母参数（-a, -p, -d, -D, -l, -t）
	flag.StringVar(&cfg.ListenAddr, "a", cfg.ListenAddr, "HTTP listen address")
	flag.IntVar(&cfg.Port, "p", cfg.Port, "HTTP listen port")
	flag.StringVar(&cfg.DataDir, "d", cfg.DataDir, "Directory for database storage")
	flag.StringVar(&cfg.DNSTapPath, "D", "", "DNSTap socket path")
	flag.StringVar(&cfg.LogFilePath, "l", "", "Log file path")
	flag.IntVar(&cfg.CacheTTLDays, "t", cfg.CacheTTLDays, "Days to keep logs")
	flag.IntVar(&cfg.MaxSizeMB, "S", cfg.MaxSizeMB, "Max database size in MB")

	flag.Parse()

	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to create data dir %s: %v\n", cfg.DataDir, err)
		os.Exit(1)
	}

	return cfg
}

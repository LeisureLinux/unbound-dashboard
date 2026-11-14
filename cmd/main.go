// Package main is the entry point for Unbound Dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"unbound-dashboard/api"
	"unbound-dashboard/core"
	"unbound-dashboard/database"
	"unbound-dashboard/ingestor"
)

// Version is overridden at build time with:
//
//	go build -ldflags "-X main.Version=v0.3.0" ./cmd/
//
// The fallback keeps `go run ./cmd/` working without ldflags.
var Version = "dev"

func main() {
	flag.Usage = usage
	cfg := core.LoadConfig()

	if cfg.VersionFlag {
		fmt.Println(Version)
		return
	}
	if len(os.Args) == 1 {
		usage()
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 配置错误: %v\n\n", err)
		usage()
		os.Exit(1)
	}
	codes, _ := core.ParseBlockRCodes(cfg.BlockRCodes) // already validated

	if cfg.TestConfig {
		fmt.Println("config OK!")
		return
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatalf("❌ 创建数据目录 %s 失败: %v", cfg.DataDir, err)
	}

	fmt.Printf("🚀 Starting Unbound Dashboard %s...\n", Version)
	fmt.Printf("   📂 Data Dir        : %s\n", cfg.DataDir)
	fmt.Printf("   🎧 Listen Address  : %s:%d\n", cfg.ListenAddr, cfg.Port)
	if cfg.DNSTapPath != "" {
		fmt.Printf("   🦐 DNSTap Socket   : %s (mode %04o)\n", cfg.DNSTapPath, cfg.SocketMode)
	} else {
		fmt.Printf("   📄 Log File        : %s\n", cfg.LogFilePath)
	}

	db, err := database.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("❌ Database init failed: %v", err)
	}
	defer db.Close()

	// Batched writer: one transaction per 64 records / 10ms instead of one
	// transaction per DNS frame.
	writer := database.NewWriter(db, cfg.QueueSize, cfg.BatchSize, cfg.FlushMS)
	defer writer.Close()

	edge := ingestor.NewEdge(writer, cfg, codes)
	allowed, err := ingestor.ParseMessageTypes(cfg.DNSTapTypes)
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	merger := ingestor.NewMerger(8192, 10*time.Second, allowed)

	var parser ingestor.Parser
	if cfg.DNSTapPath != "" {
		parser = ingestor.NewDnstapReader(cfg.DNSTapPath, cfg, edge, merger)
	} else {
		parser = ingestor.NewLogReader(cfg.LogFilePath, cfg.LogFromStart, edge)
	}
	defer parser.Close()

	// Periodic maintenance: retention, size cap, and merger timeouts.
	stopMaint := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		db.CleanupOldRecords(cfg.CacheTTLDays)
		db.CleanupBySize(int64(cfg.MaxSizeMB))
		for {
			select {
			case <-stopMaint:
				return
			case <-ticker.C:
				db.CleanupOldRecords(cfg.CacheTTLDays)
				db.CleanupBySize(int64(cfg.MaxSizeMB))
			}
		}
	}()
	defer close(stopMaint)

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopMaint:
				return
			case <-ticker.C:
				if r, ok := parser.(*ingestor.DnstapReader); ok {
					r.FlushTimeouts()
				}
			}
		}
	}()

	// Ingestor errors are fatal: the old code printed them but kept serving a
	// frozen dashboard forever.
	ingestErr := make(chan error, 1)
	go func() {
		log.Printf("🔄 启动数据摄入: %s", parser.GetPath())
		if err := parser.Start(writer); err != nil {
			ingestErr <- err
		}
	}()

	handler := api.NewHandler(db, cfg, Version)
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.Port)
	server := &http.Server{
		Addr:              addr,
		Handler:           handler.GetRouter(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Go 1.24+ opens TCP listeners as MPTCP by default. CVE-2026-98432's
	// demonstrated RCE path needs an MPTCP listener, so opt out explicitly.
	// (This does not repair the kernel; it still needs updating.)
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatalf("❌ Listen error: %v", err)
	}

	fmt.Printf("✅ Dashboard starting at http://%s\n", addr)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()

	select {
	case sig := <-shutdown:
		log.Printf("🛑 收到 %s，正在关闭…", sig)
	case err := <-ingestErr:
		log.Printf("❌ 数据摄入致命错误: %v", err)
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("❌ HTTP server 错误: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	_ = parser.Close()
	writer.Close()
}

func usage() {
	fmt.Fprintf(os.Stderr, "Unbound Dashboard %s\n", Version)
	fmt.Fprintf(os.Stderr, "GitHub: https://github.com/LeisureLinux/unbound-dashboard/\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Data source (exactly one required):\n")
	fmt.Fprintf(os.Stderr, "  -D, --dnstap PATH          DNSTap unix socket path\n")
	fmt.Fprintf(os.Stderr, "  -l, --log-file PATH        Unbound verbose log file\n\n")
	fmt.Fprintf(os.Stderr, "HTTP / storage:\n")
	fmt.Fprintf(os.Stderr, "  -a, --addr ADDR            HTTP listen address (default 127.0.0.1)\n")
	fmt.Fprintf(os.Stderr, "  -p, --port PORT            HTTP listen port (default 9153)\n")
	fmt.Fprintf(os.Stderr, "  -d, --data-dir DIR         SQLite directory (default /var/lib/unbound)\n")
	fmt.Fprintf(os.Stderr, "  -t, --ttl DAYS             Retention days (default 90)\n")
	fmt.Fprintf(os.Stderr, "  -S, --size MB              Max DB size (default 200)\n\n")
	fmt.Fprintf(os.Stderr, "Transforms (DNS-collector style):\n")
	fmt.Fprintf(os.Stderr, "  -i, --ignore-domains LIST  Comma separated domain suffixes to drop\n")
	fmt.Fprintf(os.Stderr, "  -b, --block-rcodes LIST    Rcodes counted as blocked (default NXDOMAIN,REFUSED; empty = policy only)\n")
	fmt.Fprintf(os.Stderr, "  -y, --dnstap-types LIST    DNSTap message types (default CLIENT_QUERY,CLIENT_RESPONSE)\n")
	fmt.Fprintf(os.Stderr, "  -A, --anonymize-ip         Hash client IPs before storage\n")
	fmt.Fprintf(os.Stderr, "  -r, --log-from-start       Read whole log file at startup (default true)\n\n")
	fmt.Fprintf(os.Stderr, "DNSTap socket / writer:\n")
	fmt.Fprintf(os.Stderr, "  -m, --socket-mode OCTAL    Socket permissions (default 0660)\n")
	fmt.Fprintf(os.Stderr, "  -g, --socket-group GROUP   Socket group (default unbound)\n")
	fmt.Fprintf(os.Stderr, "  -q, --queue-size N         Ingest queue capacity (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  -B, --batch-size N         Records per transaction (default 64)\n")
	fmt.Fprintf(os.Stderr, "  -f, --flush-ms N           Max flush delay in ms (default 10)\n\n")
	fmt.Fprintf(os.Stderr, "Other:\n")
	fmt.Fprintf(os.Stderr, "  -P, --debug-public         Allow /debug from non-loopback clients\n")
	fmt.Fprintf(os.Stderr, "  -k, --debug-token TOKEN    Require a bearer token for /debug\n")
	fmt.Fprintf(os.Stderr, "  -T, --test-config          Validate configuration and exit\n")
	fmt.Fprintf(os.Stderr, "  -V, --version              Show version\n")
	fmt.Fprintf(os.Stderr, "  -h, --help                 Show help\n")
}

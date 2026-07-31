// Package main is the entry point for Unbound Dashboard.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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

const Version = "v0.2.42.20260731090827"

func main() {
	// 预处理参数：将 --xxx 转换为 -x（双横杠单词 → 单横杠字母）
	for i := 1; i < len(os.Args); i++ {
		if len(os.Args[i]) > 2 && os.Args[i][:2] == "--" {
			word := os.Args[i][2:] // 去掉 --
			switch word {
			case "version":
				os.Args[i] = "-V"
			case "help":
				os.Args[i] = "-h"
			case "addr":
				os.Args[i] = "-a"
			case "port":
				os.Args[i] = "-p"
			case "data-dir":
				os.Args[i] = "-d"
			case "dnstap":
				os.Args[i] = "-D"
			case "log-file":
				os.Args[i] = "-l"
			case "ttl":
				os.Args[i] = "-t"
			case "size":
				os.Args[i] = "-S"
			}
		}
	}

	// 处理 -V 和 --version
	for _, arg := range os.Args[1:] {
		if arg == "-V" || arg == "--version" {
			fmt.Println(Version)
			os.Exit(0)
		}
	}

	// 自定义帮助信息，增加 GitHub 地址
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Unbound Dashboard %s\n", Version)
		fmt.Fprintf(os.Stderr, "GitHub: https://github.com/LeisureLinux/unbound-dashboard/\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -a, --addr string       HTTP listen address (default: \"127.0.0.1\")\n")
		fmt.Fprintf(os.Stderr, "  -p, --port int          HTTP listen port (default: 9153)\n")
		fmt.Fprintf(os.Stderr, "  -d, --data-dir string   Directory for database storage (default: \"/var/lib/unbound\")\n")
		fmt.Fprintf(os.Stderr, "  -D, --dnstap string     DNSTap socket path\n")
		fmt.Fprintf(os.Stderr, "  -l, --log-file string   DNS Server Log file path\n")
		fmt.Fprintf(os.Stderr, "  -t, --ttl int           Days to keep logs in database storage (default: 90)\n")
		fmt.Fprintf(os.Stderr, "  -S, --size int          Max database size in MB (default: 200, max: 9999)\n")
		fmt.Fprintf(os.Stderr, "  -V, --version           Show version\n")
		fmt.Fprintf(os.Stderr, "  -h, --help              Show help\n")
	}

	cfg := core.LoadConfig()

	// 校验 ttl 范围
	if cfg.CacheTTLDays < 1 {
		cfg.CacheTTLDays = 90
	} else if cfg.CacheTTLDays > 9999 {
		cfg.CacheTTLDays = 9999
	}

	// 校验 MaxSizeMB 范围
	if cfg.MaxSizeMB < 1 {
		cfg.MaxSizeMB = 200
	} else if cfg.MaxSizeMB > 9999 {
		cfg.MaxSizeMB = 9999
	}

	// 没有参数时显示 help
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	// 必须指定数据源
	if cfg.DNSTapPath == "" && cfg.LogFilePath == "" {
		fmt.Fprintf(os.Stderr, "❌ 错误: 必须指定数据源 (-D/--dnstap 或 -l/--log-file)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("🚀 Starting Unbound Dashboard %s...\n", Version)
	fmt.Printf("   📂 Data Dir        : %s\n", cfg.DataDir)
	fmt.Printf("   🎧 Listen Address  : %s:%d\n", cfg.ListenAddr, cfg.Port)
	
	if cfg.DNSTapPath != "" {
		fmt.Printf("   🦐 DNSTap Socket   : %s\n", cfg.DNSTapPath)
	} else {
		fmt.Printf("   📄 Log File        : %s\n", cfg.LogFilePath)
	}

	db, err := database.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("❌ Database init failed: %v", err)
	}
	defer db.Close()

	// 启动定时清理任务（每小时清理一次过期数据 + 检查数据库大小）
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			db.CleanupOldRecords(cfg.CacheTTLDays)
			db.CleanupBySize(int64(cfg.MaxSizeMB))
			<-ticker.C
		}
	}()

	var parser ingestor.Parser
	if cfg.DNSTapPath != "" {
		parser = ingestor.NewDnstapReader(cfg.DNSTapPath)
	} else {
		parser = ingestor.NewLogReader(cfg.LogFilePath)
	}

	// 启动数据摄入，错误直接打印到 stderr
	go func() {
		fmt.Println("🔄 正在启动数据摄入...")
		if err := parser.Start(db); err != nil {
			fmt.Printf("❌ 数据摄入错误: %v\n", err)
			log.Fatalf("Ingestor fatal error: %v", err)
		}
	}()

	handler := api.NewHandler(db, cfg)
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: handler.GetRouter(),
	}

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		close(idleConnsClosed)
	}()

	fmt.Printf("✅ Dashboard starting at http://%s\n", addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Listen error: %v", err)
	}
	<-idleConnsClosed
}

// Package database provides storage abstraction over SQLite.
package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"unbound-dashboard/core"

	_ "github.com/mattn/go-sqlite3" // SQLite driver (CGO)
)

// StatItem represents a top-list entry.
type StatItem struct {
	Name  string
	Value int64
}

// Database handles all persistence operations.
type Database struct {
	conn *sql.DB
}

// New initializes the database connection and creates necessary tables.
func New(dataDir string) (*Database, error) {
	dbPath := fmt.Sprintf("%s/dashboard.db", dataDir)
	conn, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	createSQL := `
	CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp REAL NOT NULL,
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		qtype TEXT NOT NULL,
		response TEXT DEFAULT '',
		rcode TEXT DEFAULT 'NOERROR',
		cache_hit BOOLEAN DEFAULT 0,
		blocked BOOLEAN DEFAULT 0,
		block_reason TEXT DEFAULT '',
		dnssec_status TEXT DEFAULT '',
		UNIQUE(client_ip, domain, qtype, timestamp)
	);

	-- Indexes for efficient queries
	CREATE INDEX IF NOT EXISTS idx_ts ON query_log(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_domain ON query_log(domain);
	CREATE INDEX IF NOT EXISTS idx_blocked ON query_log(blocked);
	`

	if _, err := conn.Exec(createSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	fmt.Println("✅ Database initialized successfully")
	return &Database{conn: conn}, nil
}

// InsertRecord adds a new DNS query record, ignoring duplicates via UNIQUE constraint.
func (db *Database) InsertRecord(record core.QueryRecord) error {
	stmt := `INSERT OR IGNORE INTO query_log 
		(timestamp, client_ip, domain, qtype, response, rcode, cache_hit, blocked, block_reason, dnssec_status) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := db.conn.Exec(stmt,
		record.Timestamp,
		record.ClientIP,
		record.Domain,
		record.QType,
		record.Response,
		record.RCode,
		record.CacheHit,
		record.Blocked,
		record.BlockReason,
		record.DNSSECStatus,
	)
	return err
}

// Close terminates the database connection.

// GetConn exposes the underlying *sql.DB for advanced operations like debugging.
func (db *Database) GetConn() *sql.DB {
	return db.conn
}
func (db *Database) Close() {
	if db.conn != nil {
		db.conn.Close()
	}
}

// GetStats fetches summary statistics.
func (db *Database) GetStats() map[string]int64 {
	rows, _ := db.conn.Query(`SELECT COUNT(*), COUNT(CASE WHEN blocked THEN 1 END) FROM query_log`)
	var total, blocked int64
	if rows.Next() {
		rows.Scan(&total, &blocked)
	}
	return map[string]int64{
		"TotalQueries":    total,
		"BlockedQueries":  blocked,
	}
}

/* ================================================================== */
/*  Aggregation helpers for dashboard                                  */
/* ================================================================== */

// GetTotalQueries returns total number of records.
func (db *Database) GetTotalQueries() int64 {
	var total int64
	db.conn.QueryRow("SELECT COUNT(*) FROM query_log").Scan(&total)
	return total
}

// GetBlockedQueries returns number of blocked/rejected records.
func (db *Database) GetBlockedQueries() int64 {
	var blocked int64
	db.conn.QueryRow("SELECT COUNT(*) FROM query_log WHERE blocked = 1").Scan(&blocked)
	return blocked
}

// TopQueries returns the top-N most queried domains.
func (db *Database) TopQueries(limit int) []StatItem {
	rows, err := db.conn.Query(
		"SELECT domain, COUNT(*) as cnt FROM query_log GROUP BY domain ORDER BY cnt DESC LIMIT ?", limit)
	if err != nil { return nil }
	defer rows.Close()

	var items []StatItem
	for rows.Next() {
		var s StatItem
		rows.Scan(&s.Name, &s.Value)
		items = append(items, s)
	}
	return items
}

// RejectedQueries returns the top-N rejected domains.
// Excludes normal DNS behaviors: NXDOMAIN (domain not found), SERVFAIL (server error).
// These appear as "blocked" but they're usually just missing/invalid domains.
func (db *Database) RejectedQueries(limit int) []StatItem {
	rows, err := db.conn.Query(
		"SELECT domain, COUNT(*) as cnt FROM query_log WHERE blocked = 1 GROUP BY domain ORDER BY cnt DESC LIMIT ?", limit)
	if err != nil { return nil }
	defer rows.Close()

	var items []StatItem
	for rows.Next() {
		var s StatItem
		rows.Scan(&s.Name, &s.Value)
		items = append(items, s)
	}
	return items
}


// GetOldestTimestamp returns the timestamp of the oldest record.
func (db *Database) GetOldestTimestamp() string {
	var ts float64
	err := db.conn.QueryRow("SELECT MIN(timestamp) FROM query_log").Scan(&ts)
	if err != nil || ts == 0 {
		return ""
	}
	// Convert Unix timestamp to formatted string
	t := time.Unix(int64(ts), 0)
	return t.Format("2006-01-02 15:04:05")
}

// CleanupOldRecords removes records older than ttlDays.
func (db *Database) CleanupOldRecords(ttlDays int) {
	cutoff := time.Now().AddDate(0, 0, -ttlDays).Unix()
	_, err := db.conn.Exec("DELETE FROM query_log WHERE timestamp < ?", cutoff)
	if err != nil {
		log.Printf("⚠️  Cleanup failed: %v", err)
	}
}

// GetDBSizeMB returns the database file size in MB.
func (db *Database) GetDBSizeMB() int64 {
	var size int64
	err := db.conn.QueryRow("SELECT page_count * page_size / 1048576 AS size_mb FROM pragma_page_count(), pragma_page_size()").Scan(&size)
	if err != nil {
		log.Printf("⚠️  Failed to get DB size: %v", err)
		return 0
	}
	return size
}

// CleanupBySize removes oldest records to reduce DB size to half of maxMB when exceeded.
func (db *Database) CleanupBySize(maxMB int64) {
	size := db.GetDBSizeMB()
	if size <= maxMB {
		return
	}
	
	// 获取总记录数
	var total int64
	err := db.conn.QueryRow("SELECT COUNT(*) FROM query_log").Scan(&total)
	if err != nil {
		log.Printf("⚠️  Failed to count records: %v", err)
		return
	}
	
	// 删除一半的记录（按时间排序，保留最新的）
	deleteCount := total / 2
	if deleteCount == 0 {
		return
	}
	
	_, err = db.conn.Exec("DELETE FROM query_log WHERE id IN (SELECT id FROM query_log ORDER BY timestamp ASC LIMIT ?)", deleteCount)
	if err != nil {
		log.Printf("⚠️  Size cleanup failed: %v", err)
		return
	}
	
	// 执行 VACUUM 回收空间
	_, err = db.conn.Exec("VACUUM")
	if err != nil {
		log.Printf("⚠️  VACUUM failed: %v", err)
		return
	}
	
	newSize := db.GetDBSizeMB()
	log.Printf("🧹 数据库大小 %dMB 超过限制 %dMB，已删除 %d 条记录，当前大小 %dMB", size, maxMB, deleteCount, newSize)
}

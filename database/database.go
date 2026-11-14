// Package database provides storage over SQLite, including a batched writer.
//
// The writer follows DNS-collector's worker model: ingestors push records
// into a buffered channel, a single writer goroutine accumulates batches and
// commits them in one transaction with a prepared statement. This removes one
// SQLite transaction per DNS frame from the hot path and gives the pipeline
// explicit backpressure (records_dropped_total) instead of silent blocking.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"unbound-dashboard/core"

	_ "github.com/mattn/go-sqlite3" // SQLite driver (CGO)
)

// StatItem represents a top-list entry. JSON tags are lowercase so /stats
// matches the documented API shape instead of emitting "Name"/"Value".
type StatItem struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// Database handles all persistence operations.
type Database struct {
	conn *sql.DB
}

const createSQL = `
CREATE TABLE IF NOT EXISTS query_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp REAL NOT NULL,
	client_ip TEXT NOT NULL DEFAULT '',
	domain TEXT NOT NULL,
	qtype TEXT NOT NULL DEFAULT '',
	response TEXT DEFAULT '',
	rcode TEXT DEFAULT 'NOERROR',
	cache_hit BOOLEAN DEFAULT 0,
	blocked BOOLEAN DEFAULT 0,
	block_reason TEXT DEFAULT '',
	dnssec_status TEXT DEFAULT '',
	operation TEXT DEFAULT '',
	identity TEXT DEFAULT '',
	latency_ms REAL DEFAULT 0,
	count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_ts       ON query_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_domain   ON query_log(domain);
CREATE INDEX IF NOT EXISTS idx_blocked  ON query_log(blocked);
CREATE INDEX IF NOT EXISTS idx_rcode    ON query_log(rcode);
`

const insertSQL = `INSERT INTO query_log
	(timestamp, client_ip, domain, qtype, response, rcode, cache_hit,
	 blocked, block_reason, dnssec_status, operation, identity, latency_ms, count)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// New initializes the database connection and creates/migrates tables.
func New(dataDir string) (*Database, error) {
	dbPath := fmt.Sprintf("%s/dashboard.db", dataDir)
	conn, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	conn.SetMaxOpenConns(2)

	db := &Database{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Exec(createSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}
	fmt.Println("✅ Database initialized successfully")
	return db, nil
}

// migrate upgrades databases created by v0.2.x.
//
// The old schema had UNIQUE(client_ip, domain, qtype, timestamp) which, with
// integer-second timestamps and an empty client_ip in DNSTap mode, collapsed
// all repeated queries within a second. It also lacked the count/operation/
// identity/latency columns. SQLite cannot drop an autoindex, so the table is
// rebuilt. Existing rows keep count=1 (their dedup already lost the repeats).
func (db *Database) migrate() error {
	rows, err := db.conn.Query(`PRAGMA table_info(query_log)`)
	if err != nil {
		return fmt.Errorf("inspect table: %w", err)
	}
	var hasTable bool
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan table info: %w", err)
		}
		hasTable = true
		cols[name] = true
	}
	rows.Close()
	if !hasTable || (cols["count"] && cols["operation"] && cols["identity"] && cols["latency_ms"]) {
		return nil
	}

	log.Printf("🔄 Migrating query_log schema (v0.2.x -> v0.3.x)…")
	const migration = `
BEGIN;
CREATE TABLE query_log_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp REAL NOT NULL,
	client_ip TEXT NOT NULL DEFAULT '',
	domain TEXT NOT NULL,
	qtype TEXT NOT NULL DEFAULT '',
	response TEXT DEFAULT '',
	rcode TEXT DEFAULT 'NOERROR',
	cache_hit BOOLEAN DEFAULT 0,
	blocked BOOLEAN DEFAULT 0,
	block_reason TEXT DEFAULT '',
	dnssec_status TEXT DEFAULT '',
	operation TEXT DEFAULT '',
	identity TEXT DEFAULT '',
	latency_ms REAL DEFAULT 0,
	count INTEGER NOT NULL DEFAULT 1
);
INSERT INTO query_log_new
	(timestamp, client_ip, domain, qtype, response, rcode, cache_hit,
	 blocked, block_reason, dnssec_status)
	SELECT timestamp, client_ip, domain, qtype, response, rcode, cache_hit,
	       blocked, block_reason, dnssec_status FROM query_log;
DROP TABLE query_log;
ALTER TABLE query_log_new RENAME TO query_log;
CREATE INDEX idx_ts      ON query_log(timestamp DESC);
CREATE INDEX idx_domain  ON query_log(domain);
CREATE INDEX idx_blocked ON query_log(blocked);
CREATE INDEX idx_rcode   ON query_log(rcode);
COMMIT;`
	if _, err := db.conn.Exec(migration); err != nil {
		_, _ = db.conn.Exec("ROLLBACK")
		return fmt.Errorf("migrate table: %w", err)
	}
	return nil
}

// InsertRecord inserts a single record immediately. Used by tests and tools;
// the ingestion path uses Writer instead.
func (db *Database) InsertRecord(rec core.QueryRecord) error {
	_, err := db.conn.Exec(insertSQL, insertArgs(rec)...)
	return err
}

func insertArgs(r core.QueryRecord) []any {
	count := r.Count
	if count < 1 {
		count = 1
	}
	return []any{
		r.Timestamp, r.ClientIP, core.NormalizeDomain(r.Domain), r.QType,
		r.Response, r.RCode, r.CacheHit, r.Blocked, r.BlockReason,
		r.DNSSECStatus, r.Operation, r.Identity, r.LatencyMS, count,
	}
}

func (db *Database) GetConn() *sql.DB { return db.conn }

func (db *Database) Close() {
	if db.conn != nil {
		_ = db.conn.Close()
	}
}

/* ================================================================== */
/*  Batched writer                                                     */
/* ================================================================== */

// Writer is a core.Sink that batches records into SQLite transactions.
type Writer struct {
	db      *Database
	ch      chan core.QueryRecord
	batch   int
	flush   time.Duration
	close   sync.Once
	wg      sync.WaitGroup
	onError func(error)
}

// NewWriter starts the writer goroutine.
func NewWriter(db *Database, queueSize, batchSize, flushMS int) *Writer {
	w := &Writer{
		db:    db,
		ch:    make(chan core.QueryRecord, queueSize),
		batch: batchSize,
		flush: time.Duration(flushMS) * time.Millisecond,
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// Enqueue never blocks the ingestor. If the queue is full the record is
// dropped and the drop counter is incremented (DNS-collector emits the same
// "buffer is full" signal). Preserving ingest liveness matters more here than
// preserving every frame of a burst.
func (w *Writer) Enqueue(rec core.QueryRecord) {
	core.Metrics.RecordsEnqueued.Add(1)
	select {
	case w.ch <- rec:
	default:
		core.Metrics.RecordsDropped.Add(1)
	}
}

func (w *Writer) run() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flush)
	defer ticker.Stop()

	pending := make([]core.QueryRecord, 0, w.batch)
	flush := func() {
		if len(pending) == 0 {
			return
		}
		if err := w.commit(pending); err != nil {
			core.Metrics.InsertErrors.Add(1)
			log.Printf("⚠️  batch insert failed: %v", err)
		} else {
			core.Metrics.RecordsInserted.Add(uint64(len(pending)))
			core.Metrics.BatchesFlushed.Add(1)
		}
		pending = pending[:0]
	}

	for {
		select {
		case rec, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			pending = append(pending, rec)
			if len(pending) >= w.batch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *Writer) commit(batch []core.QueryRecord) error {
	tx, err := w.db.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, rec := range batch {
		if _, err := stmt.Exec(insertArgs(rec)...); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Close drains the queue and waits for the final transaction.
func (w *Writer) Close() {
	w.close.Do(func() {
		close(w.ch)
		w.wg.Wait()
	})
}

/* ================================================================== */
/*  Queries                                                            */
/* ================================================================== */

// GetStats returns weighted totals (SUM(count) rather than COUNT(*)).
func (db *Database) GetStats() map[string]int64 {
	var total, blocked int64
	_ = db.conn.QueryRow(`SELECT COALESCE(SUM(count),0),
		COALESCE(SUM(CASE WHEN blocked THEN count ELSE 0 END),0) FROM query_log`).
		Scan(&total, &blocked)
	return map[string]int64{"TotalQueries": total, "BlockedQueries": blocked}
}

func (db *Database) GetTotalQueries() int64 {
	var total int64
	_ = db.conn.QueryRow("SELECT COALESCE(SUM(count),0) FROM query_log").Scan(&total)
	return total
}

func (db *Database) GetBlockedQueries() int64 {
	var blocked int64
	_ = db.conn.QueryRow("SELECT COALESCE(SUM(count),0) FROM query_log WHERE blocked = 1").Scan(&blocked)
	return blocked
}

// RCodeStats returns a breakdown so NXDOMAIN/REFUSED/SERVFAIL can be shown
// separately instead of being lumped into a misleading "blocked" number.
func (db *Database) RCodeStats() []StatItem {
	rows, err := db.conn.Query(`SELECT COALESCE(NULLIF(rcode,''),'UNKNOWN') AS rc,
		SUM(count) AS cnt FROM query_log GROUP BY rc ORDER BY cnt DESC LIMIT 10`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return scanStats(rows)
}

func (db *Database) TopQueries(limit int) []StatItem {
	rows, err := db.conn.Query(`SELECT domain, SUM(count) AS cnt FROM query_log
		WHERE blocked = 0 GROUP BY domain ORDER BY cnt DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return scanStats(rows)
}

// RejectedQueries returns the top-N policy-blocked or anomalous domains.
// It no longer claims to exclude NXDOMAIN: that is controlled by
// --block-rcodes, and the UI now says "拦截/异常" rather than "blocked".
func (db *Database) RejectedQueries(limit int) []StatItem {
	rows, err := db.conn.Query(`SELECT domain, SUM(count) AS cnt FROM query_log
		WHERE blocked = 1 GROUP BY domain ORDER BY cnt DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return scanStats(rows)
}

func scanStats(rows *sql.Rows) []StatItem {
	var items []StatItem
	for rows.Next() {
		var s StatItem
		if err := rows.Scan(&s.Name, &s.Value); err == nil {
			items = append(items, s)
		}
	}
	return items
}

func (db *Database) GetOldestTimestamp() string {
	var ts float64
	if err := db.conn.QueryRow("SELECT MIN(timestamp) FROM query_log").Scan(&ts); err != nil || ts == 0 {
		return ""
	}
	return time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05")
}

// RecentRecords returns the newest records for /debug.
func (db *Database) RecentRecords(limit int) []string {
	rows, err := db.conn.Query(`SELECT domain, qtype, rcode, response, operation
		FROM query_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d, qt, rc, res, op string
		if err := rows.Scan(&d, &qt, &rc, &res, &op); err != nil {
			continue
		}
		if res == "" {
			res = op
		}
		out = append(out, fmt.Sprintf("[%s] %s (%s) -> %s", rc, d, qt, res))
	}
	return out
}

/* ================================================================== */
/*  Retention                                                          */
/* ================================================================== */

func (db *Database) CleanupOldRecords(ttlDays int) {
	cutoff := float64(time.Now().AddDate(0, 0, -ttlDays).Unix())
	if _, err := db.conn.Exec("DELETE FROM query_log WHERE timestamp < ?", cutoff); err != nil {
		log.Printf("⚠️  Cleanup failed: %v", err)
	}
}

func (db *Database) GetDBSizeMB() int64 {
	var size int64
	if err := db.conn.QueryRow("SELECT page_count * page_size / 1048576 FROM pragma_page_count(), pragma_page_size()").Scan(&size); err != nil {
		log.Printf("⚠️  Failed to get DB size: %v", err)
		return 0
	}
	return size
}

// CleanupBySize removes the oldest rows until the file is back under the cap.
func (db *Database) CleanupBySize(maxMB int64) {
	size := db.GetDBSizeMB()
	if size <= maxMB {
		return
	}
	var total int64
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM query_log").Scan(&total); err != nil {
		log.Printf("⚠️  Failed to count records: %v", err)
		return
	}
	if total == 0 {
		return
	}
	deleteCount := total / 4 // trim in smaller steps than the old 50% cliff
	if deleteCount == 0 {
		deleteCount = 1
	}
	if _, err := db.conn.Exec(`DELETE FROM query_log WHERE id IN
		(SELECT id FROM query_log ORDER BY timestamp ASC LIMIT ?)`, deleteCount); err != nil {
		log.Printf("⚠️  Size cleanup failed: %v", err)
		return
	}
	if _, err := db.conn.Exec("PRAGMA incremental_vacuum"); err != nil {
		log.Printf("⚠️  incremental_vacuum failed: %v", err)
	}
	log.Printf("🧹 数据库 %dMB > 限制 %dMB，已删除 %d 行，当前 %dMB",
		size, maxMB, deleteCount, db.GetDBSizeMB())
}

// QuoteIdentifier guards against injecting through user-supplied values in
// dynamic SQL. (Currently unused; kept for future filter expressions.)
func QuoteIdentifier(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

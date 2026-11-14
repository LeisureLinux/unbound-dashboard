package database

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"unbound-dashboard/core"

	_ "github.com/mattn/go-sqlite3"
)

func openLegacy(path string) (*sql.DB, error) {
	return sql.Open("sqlite3", path)
}

func nowUnix() int64 { return time.Now().Unix() }

func TestWriter_BatchesAndWeightsCounts(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w := NewWriter(db, 64, 8, 5)
	for i := 0; i < 25; i++ {
		w.Enqueue(core.QueryRecord{
			Domain: "repeat.test", Timestamp: float64(1700000000 + i), Count: 1,
		})
	}
	w.Close()

	// The old UNIQUE constraint collapsed all identical queries within one
	// second; here every record must survive.
	if got := db.GetTotalQueries(); got != 25 {
		t.Errorf("total = %d, want 25", got)
	}
	if got := len(db.TopQueries(10)); got != 1 {
		t.Errorf("top queries = %d groups, want 1", got)
	}
	if got := db.TopQueries(10)[0].Value; got != 25 {
		t.Errorf("top count = %d, want 25", got)
	}
}

func TestInsertRecord_DefaultCount(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InsertRecord(core.QueryRecord{Domain: "X.Test.", Timestamp: 1, RCode: "REFUSED"}); err != nil {
		t.Fatal(err)
	}
	if got := db.GetTotalQueries(); got != 1 {
		t.Errorf("total = %d, want 1 (Count defaults to 1)", got)
	}
	items := db.RCodeStats()
	if len(items) != 1 || items[0].Name != "REFUSED" {
		t.Errorf("rcode stats = %+v", items)
	}
}

func TestMigrate_LegacySchema(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "dashboard.db")
	// Simulate a v0.2.x database with the deduplicating UNIQUE constraint.
	legacy, err := openLegacy(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE query_log (
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
	); INSERT INTO query_log (timestamp,client_ip,domain,qtype,rcode)
	   VALUES (1700000000,'','old.test','A','NOERROR')`)
	if err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()

	db, err := New(dir)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	defer db.Close()
	if got := db.GetTotalQueries(); got != 1 {
		t.Errorf("legacy row lost during migration: total=%d", got)
	}
	// New inserts must no longer be deduplicated.
	for i := 0; i < 3; i++ {
		if err := db.InsertRecord(core.QueryRecord{Domain: "old.test", Timestamp: 1700000001, Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if got := db.GetTotalQueries(); got != 4 {
		t.Errorf("total after migration = %d, want 4", got)
	}
}

func TestCleanupOldRecords(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.InsertRecord(core.QueryRecord{Domain: "old.test", Timestamp: 1, Count: 1})
	_ = db.InsertRecord(core.QueryRecord{Domain: "new.test", Timestamp: float64(nowUnix()), Count: 1})
	db.CleanupOldRecords(90)
	if got := db.GetTotalQueries(); got != 1 {
		t.Errorf("total after cleanup = %d, want 1", got)
	}
}

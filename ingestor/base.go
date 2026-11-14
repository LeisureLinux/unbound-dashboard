// Package ingestor: Unbound verbose-log tailer.
package ingestor

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"unbound-dashboard/core"
)

// Unbound log lines look like (rsyslog + verbosity 2):
//
//	Oct 13 21:23:01 host[1234:0] info: 192.0.2.1 example.com. A IN NOERROR 0.000000 0 0
//
// and query-only lines without a reply rcode.
var (
	syslogRe    = regexp.MustCompile(`^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\[(\d+:\d+)\]\s+(\w+):\s+(\S+)\s+(\S+)\s+(\S+)\s+IN\s+(\S+)(?:\s+(.*))?$`)
	queryOnlyRe = regexp.MustCompile(`^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\[(\d+:\d+)\]\s+(\w+):\s+(\S+)\s+(\S+)\s+(\S+)\s+IN$`)
	isoRe       = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})`)
)

// LogReader tails a log file with inode-aware rotation handling and
// delimiter-safe offset tracking.
type LogReader struct {
	path      string
	edge      *Edge
	mu        sync.Mutex
	closed    bool
	stop      chan struct{}
	wg        sync.WaitGroup
	fromStart bool
}

func NewLogReader(path string, fromStart bool, edge *Edge) *LogReader {
	return &LogReader{path: path, edge: edge, stop: make(chan struct{}), fromStart: fromStart}
}

func (r *LogReader) GetPath() string { return r.path }

// Start implements a two-phase ingestion strategy:
//  1. Optionally scan existing content (history) — keeping the file's own
//     timestamps instead of stamping everything with time.Now().
//  2. Tail with poll + Stat; if the inode changes (logrotate create), reopen.
func (r *LogReader) Start(sink core.Sink) error {
	f, st, err := openLog(r.path)
	if err != nil {
		return err
	}
	defer f.Close()

	offset := int64(0)
	if !r.fromStart {
		offset = st.Size()
	} else {
		offset, _ = r.scan(f, st.Size())
	}
	inode := inodeOf(st)
	lastSize := st.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return nil
		case <-ticker.C:
		}

		cur, err := os.Stat(r.path)
		if err != nil {
			if os.IsNotExist(err) {
				core.Metrics.LogRotations.Add(1)
				log.Printf("⚠️  日志文件暂时消失: %s", r.path)
				continue
			}
			continue
		}

		// Rotation: different inode (rename + create) or truncation.
		if inodeOf(cur) != inode || cur.Size() < lastSize {
			core.Metrics.LogRotations.Add(1)
			log.Printf("🔄 检测到日志轮转，重新打开 %s", r.path)
			newF, newSt, err := openLog(r.path)
			if err != nil {
				continue
			}
			_ = f.Close()
			f = newF
			inode = inodeOf(newSt)
			lastSize = newSt.Size()
			offset = 0
		}
		lastSize = cur.Size()

		if cur.Size() <= offset {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			continue
		}
		consumed, err := r.scanFrom(f, cur.Size()-offset)
		if err != nil {
			log.Printf("⚠️  读取日志失败: %v", err)
		}
		// Only advance past complete lines; a trailing partial line stays for
		// the next poll (the old code silently lost it).
		offset += consumed
		if offset > cur.Size() {
			offset = cur.Size()
		}
	}
}

// scan reads all complete lines from the beginning and returns the safe
// offset (end of the last newline-terminated line).
func (r *LogReader) scan(f *os.File, size int64) (int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	return r.scanFrom(f, size)
}

func (r *LogReader) scanFrom(f *os.File, available int64) (int64, error) {
	lr := io.LimitReader(f, available)
	br := bufio.NewReaderSize(lr, 64*1024)
	consumed := int64(0)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				consumed += int64(len(line))
				r.parseLine(strings.TrimRight(string(line), "\r\n"))
			} else {
				// Partial last line: do not consume it.
				break
			}
		}
		if err != nil {
			break
		}
	}
	return consumed, nil
}

func (r *LogReader) parseLine(line string) {
	if line == "" {
		return
	}
	var stamp, ip, domain, qtype, rcode, rest string
	var matched bool
	if m := syslogRe.FindStringSubmatch(line); len(m) > 8 {
		stamp, ip, domain, qtype, rcode, rest = m[1], m[5], m[6], m[7], m[8], m[9]
		matched = true
	} else if m := queryOnlyRe.FindStringSubmatch(line); len(m) > 7 {
		stamp, ip, domain, qtype, rcode, rest = m[1], m[5], m[6], m[7], "", ""
		matched = true
	}
	if !matched {
		return
	}
	// Reply lines give latency as the last float; capture it as a light
	// version of DNS-collector's latency transformer.
	// Unbound reply lines end with "latency ..." fields; the first one is
	// the resolution time in seconds.
	var latency float64
	if fields := strings.Fields(rest); len(fields) > 0 {
		if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
			latency = f * 1000
		}
	}
	rec := core.QueryRecord{
		Timestamp: parseLogTime(stamp),
		ClientIP:  ip,
		Domain:    core.NormalizeDomain(domain),
		QType:     strings.ToUpper(qtype),
		RCode:     strings.ToUpper(strings.TrimSpace(rcode)),
		Response:  "Reply",
		Operation: "LOG_REPLY",
		LatencyMS: latency,
		Count:     1,
	}
	if rec.RCode == "" {
		rec.RCode = "NOERROR"
		rec.Response = "Query"
		rec.Operation = "LOG_QUERY"
	}
	if rec, ok := r.edge.Prepare(rec); ok {
		r.edge.Emit(rec)
	}
}

// parseLogTime converts syslog "Oct 13 21:23:01" (or ISO) to epoch seconds.
// The year is inferred from the current year, with a rollover guard for
// December→January reads.
func parseLogTime(s string) float64 {
	now := time.Now()
	if isoRe.MatchString(s) {
		s = strings.Replace(s, " ", "T", 1)
		for _, layout := range []string{"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05"} {
			if t, err := time.Parse(layout, s); err == nil {
				return float64(t.UnixNano()) / 1e9
			}
		}
		return float64(now.UnixNano()) / 1e9
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", s, now.Location())
	if err != nil {
		return float64(now.UnixNano()) / 1e9
	}
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return float64(t.UnixNano()) / 1e9
}

func openLog(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("打开日志 %s 失败: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

// inodeOf is unix-specific; the fallback keeps it portable to other builds.
func inodeOf(fi os.FileInfo) uint64 { return fileInode(fi) }

func (r *LogReader) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	close(r.stop)
	r.mu.Unlock()
	return nil
}

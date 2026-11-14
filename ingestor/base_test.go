package ingestor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"unbound-dashboard/core"
)

func testEdge(sink core.Sink) *Edge {
	return NewEdge(sink, &core.Config{}, map[string]bool{"NXDOMAIN": true, "REFUSED": true})
}

// waitFor polls a condition without racing on the sink's internal slice.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

func TestParseLogTime_SyslogAndISO(t *testing.T) {
	syslog := parseLogTime("Oct 13 21:23:01")
	iso := parseLogTime("2024-10-13T21:23:01")
	if syslog < 1_600_000_000 || syslog > 2_000_000_000 {
		t.Errorf("syslog timestamp = %v", syslog)
	}
	if iso != 1728854581 {
		t.Errorf("iso timestamp = %v, want 1728854581", iso)
	}
}

func TestLogReader_ParsesLinesAndPreservesTimestamps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unbound.log")
	line := "Oct 13 21:23:01 host[1234:0] info: 192.0.2.1 Example.COM. A IN NXDOMAIN 0.025000 0 0\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &core.CollectSink{}
	r := NewLogReader(path, true, testEdge(sink))
	defer r.Close()
	go func() { _ = r.Start(nil) }()
	waitFor(2*time.Second, func() bool { return sink.Len() >= 1 })
	_ = r.Close()
	got := sink.Snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d records", len(got))
	}
	rec := got[0]
	if rec.Domain != "example.com" || rec.ClientIP != "192.0.2.1" || rec.RCode != "NXDOMAIN" {
		t.Errorf("record = %+v", rec)
	}
	if !rec.Blocked {
		t.Error("NXDOMAIN should be blocked with the default policy")
	}
	if rec.LatencyMS != 25 {
		t.Errorf("latency = %v ms, want 25", rec.LatencyMS)
	}
	// The original bug stamped history with time.Now() instead of the log's
	// own timestamp.
	if rec.Timestamp > 1_800_000_000 {
		t.Errorf("timestamp looks like time.Now(): %v", rec.Timestamp)
	}
}

func TestLogReader_HandlesPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unbound.log")
	part := "Oct 13 21:23:01 host[1234:0] info: 192.0.2.1 partial."
	if err := os.WriteFile(path, []byte(part), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &core.CollectSink{}
	r := NewLogReader(path, true, testEdge(sink))
	defer r.Close()
	go func() { _ = r.Start(nil) }()
	time.Sleep(100 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(" A IN NOERROR 0.0 0 0\n")
	_ = f.Close()
	waitFor(2*time.Second, func() bool { return sink.Len() >= 1 })
	_ = r.Close()
	got := sink.Snapshot()
	if len(got) != 1 || got[0].Domain != "partial" {
		t.Errorf("partial line lost or duplicated: %+v", got)
	}
}

func TestLogReader_DetectsRotationByInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unbound.log")
	line := func(d string) string {
		return "Oct 13 21:23:01 host[1234:0] info: 192.0.2.1 " + d + ". A IN NOERROR 0.0 0 0\n"
	}
	if err := os.WriteFile(path, []byte(line("before")), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &core.CollectSink{}
	r := NewLogReader(path, true, testEdge(sink))
	defer r.Close()
	go func() { _ = r.Start(nil) }()
	time.Sleep(150 * time.Millisecond)
	_ = os.Rename(path, path+".1")
	_ = os.WriteFile(path, []byte(line("after")), 0o644)
	waitFor(3*time.Second, func() bool {
		for _, rec := range sink.Snapshot() {
			if rec.Domain == "after" {
				return true
			}
		}
		return false
	})
	_ = r.Close()
	seen := map[string]bool{}
	for _, rec := range sink.Snapshot() {
		seen[rec.Domain] = true
	}
	if !seen["before"] || !seen["after"] {
		t.Errorf("rotation not handled: %v", seen)
	}
	if core.Metrics.LogRotations.Load() == 0 {
		t.Error("rotation counter not incremented")
	}
}

func TestLogReader_IgnoresGarbage(t *testing.T) {
	sink := &core.CollectSink{}
	r := NewLogReader("unused", false, testEdge(sink))
	r.parseLine("this is not an unbound query line")
	if sink.Len() != 0 {
		t.Errorf("garbage parsed: %+v", sink.Snapshot())
	}
}

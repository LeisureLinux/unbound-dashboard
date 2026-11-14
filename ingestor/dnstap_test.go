package ingestor

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"unbound-dashboard/core"
)

// writeFstrmFrame encodes one fstrm data frame.
func writeFstrmFrame(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	if _, err := c.Write(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
}

// waitForReader waits until the socket exists and accepts a connection.
func waitForReader(t *testing.T, path string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", path); err == nil {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("DNSTap socket never became available")
	return nil
}

// readCtrlFrame reads one control frame and returns (type, contentTypes).
func readCtrlFrame(t *testing.T, c net.Conn) (uint32, []string) {
	t.Helper()
	var escape, ctrlLen uint32
	if err := binary.Read(c, binary.BigEndian, &escape); err != nil {
		t.Fatal(err)
	}
	if escape != 0 {
		t.Fatalf("escape = %d, want 0", escape)
	}
	if err := binary.Read(c, binary.BigEndian, &ctrlLen); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, ctrlLen)
	if _, err := readFullBytes(c, data); err != nil {
		t.Fatal(err)
	}
	ctype := binary.BigEndian.Uint32(data[0:4])
	var cts []string
	off := 4
	for off+8 <= len(data) {
		if binary.BigEndian.Uint32(data[off:off+4]) != controlFieldContentType {
			break
		}
		off += 4
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n > len(data) {
			break
		}
		cts = append(cts, string(data[off:off+n]))
		off += n
	}
	return ctype, cts
}

func TestDnstapReader_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dnstap.sock")
	cfg := &core.Config{SocketMode: 0o600, SocketGroup: ""}
	sink := &core.CollectSink{}
	edge := NewEdge(sink, cfg, map[string]bool{"NXDOMAIN": true})
	allowed, _ := ParseMessageTypes("CLIENT_QUERY,CLIENT_RESPONSE")
	merger := NewMerger(64, 5*time.Second, allowed)
	r := NewDnstapReader(sock, cfg, edge, merger)
	defer r.Close()

	go func() { _ = r.Start(sink) }()

	c := waitForReader(t, sock)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	_, _ = c.Write(buildCtrlFrame(controlReady, []string{contentTypeDNSTap}))
	ctype, cts := readCtrlFrame(t, c)
	if ctype != controlAccept {
		t.Fatalf("expected ACCEPT, got 0x%02x", ctype)
	}
	if len(cts) != 1 || cts[0] != contentTypeDNSTap {
		t.Errorf("ACCEPT content types = %v", cts)
	}
	_, _ = c.Write(buildCtrlFrame(controlStart, nil))

	q := buildDnstapFrame(msgClientQuery, dnsQueryWire("e2e.test"), false, 1700000000, 0)
	rsp := buildDnstapFrame(msgClientResponse, dnsQueryWire("e2e.test"), true, 1700000000, 1700000001)
	writeFstrmFrame(t, c, q)
	writeFstrmFrame(t, c, rsp)

	waitFor(2*time.Second, func() bool { return sink.Len() >= 1 })
	got := sink.Snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 correlated transaction", len(got))
	}
	if got[0].Domain != "e2e.test" || got[0].Operation != "CLIENT_RESPONSE" {
		t.Errorf("record = %+v", got[0])
	}
	if core.Metrics.FramesReceived.Load() < 2 {
		t.Errorf("frames_received = %d", core.Metrics.FramesReceived.Load())
	}

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Errorf("socket mode %o is group/world writable", fi.Mode().Perm())
	}
}

func TestDnstapReader_RejectsWrongContentType(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dnstap.sock")
	cfg := &core.Config{SocketMode: 0o600, SocketGroup: ""}
	allowed, _ := ParseMessageTypes("CLIENT_QUERY,CLIENT_RESPONSE")
	r := NewDnstapReader(sock, cfg, NewEdge(&core.CollectSink{}, cfg, nil), NewMerger(16, time.Second, allowed))
	defer r.Close()
	go func() { _ = r.Start(nil) }()

	c := waitForReader(t, sock)
	defer c.Close()
	_, _ = c.Write(buildCtrlFrame(controlReady, []string{"protobuf:something.Else"}))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("server should close a connection with an unsupported content type")
	}
}

func TestDnstapReader_DoesNotRemoveRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "important.conf")
	if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &core.Config{SocketMode: 0o600}
	allowed, _ := ParseMessageTypes("CLIENT_QUERY")
	r := NewDnstapReader(path, cfg, NewEdge(&core.CollectSink{}, cfg, nil), NewMerger(16, time.Second, allowed))
	if err := r.Start(nil); err == nil {
		t.Fatal("expected refusal to unlink a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep me" {
		t.Errorf("regular file was modified: %q, %v", data, err)
	}
}

func TestDnstapReader_RejectsOversizedFrame(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dnstap.sock")
	cfg := &core.Config{SocketMode: 0o600, SocketGroup: ""}
	allowed, _ := ParseMessageTypes("CLIENT_QUERY")
	r := NewDnstapReader(sock, cfg, NewEdge(&core.CollectSink{}, cfg, nil), NewMerger(16, time.Second, allowed))
	defer r.Close()
	go func() { _ = r.Start(nil) }()

	c := waitForReader(t, sock)
	defer c.Close()
	_, _ = c.Write(buildCtrlFrame(controlReady, []string{contentTypeDNSTap}))
	_, _ = readCtrlFrame(t, c)
	_, _ = c.Write(buildCtrlFrame(controlStart, nil))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, dataFrameMaxLen+1)
	_, _ = c.Write(buf)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("server should reject an oversized frame")
	}
}

func buildCtrlFrame(ctype uint32, contentTypes []string) []byte {
	var ctrl []byte
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ctype)
	ctrl = append(ctrl, b...)
	for _, ct := range contentTypes {
		binary.BigEndian.PutUint32(b, controlFieldContentType)
		ctrl = append(ctrl, b...)
		binary.BigEndian.PutUint32(b, uint32(len(ct)))
		ctrl = append(ctrl, b...)
		ctrl = append(ctrl, []byte(ct)...)
	}
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(ctrl)))
	frame = append(frame, b...)
	return append(frame, ctrl...)
}

func readFullBytes(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

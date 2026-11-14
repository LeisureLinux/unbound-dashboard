// Package ingestor: DNSTap Frame Streams (fstrm) server.
//
// Hardening borrowed from DNS-collector's global.framestream and
// collector_dnstap settings: bounded control/data frame lengths, handshake
// and read deadlines, content-type validation, concurrent connections, no
// unlink of arbitrary paths, and a least-privilege socket mode.
package ingestor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"unbound-dashboard/core"
)

const (
	controlAccept = 0x01
	controlStart  = 0x02
	controlStop   = 0x03
	controlReady  = 0x04
	controlFinish = 0x05

	controlFieldContentType = 0x01
	contentTypeDNSTap       = "protobuf:dnstap.Dnstap"

	controlFrameMaxLen = 4064  // DNS-collector default
	dataFrameMaxLen    = 65536 // DNS-collector default
	handshakeTimeout   = 5 * time.Second
	readTimeout        = 30 * time.Second
)

// DnstapReader listens on a unix socket for Unbound's dnstap stream.
type DnstapReader struct {
	socketPath string
	mode       os.FileMode
	group      string
	edge       *Edge
	merger     *Merger
	listener   net.Listener
	mu         sync.Mutex
	closed     bool
	conns      map[net.Conn]struct{}
	wg         sync.WaitGroup
}

func NewDnstapReader(path string, cfg *core.Config, edge *Edge, merger *Merger) *DnstapReader {
	return &DnstapReader{
		socketPath: path,
		mode:       cfg.SocketMode,
		group:      cfg.SocketGroup,
		edge:       edge,
		merger:     merger,
		conns:      make(map[net.Conn]struct{}),
	}
}

func (d *DnstapReader) GetPath() string { return d.socketPath }

// Start creates the socket and serves connections until Close is called.
// Unlike the old implementation it never returns nil on a STOP frame — Unbound
// restarts routinely, and a silent exit left the dashboard serving stale data.
func (d *DnstapReader) Start(sink core.Sink) error {
	if err := d.prepareSocketPath(); err != nil {
		return err
	}
	ln, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("创建 DNSTap socket 失败: %w", err)
	}
	d.mu.Lock()
	d.listener = ln
	d.mu.Unlock()

	if err := d.applySocketPerms(); err != nil {
		log.Printf("⚠️  socket 权限设置失败: %v", err)
	}
	fmt.Printf("✅ DNSTap socket 已创建: %s (mode %04o)\n", d.socketPath, d.mode)
	fmt.Println("👂 等待 Unbound 连接...")

	for {
		conn, err := ln.Accept()
		if err != nil {
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("接受连接失败: %w", err)
		}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			_ = conn.Close()
			continue
		}
		d.conns[conn] = struct{}{}
		d.mu.Unlock()
		core.Metrics.Connects.Add(1)
		d.wg.Add(1)
		// Concurrent connections: a slow/restarting peer must not block others.
		go func() {
			defer d.wg.Done()
			defer core.Metrics.Disconnects.Add(1)
			defer func() {
				d.mu.Lock()
				delete(d.conns, conn)
				d.mu.Unlock()
			}()
			if err := d.handleConnection(conn); err != nil && !errors.Is(err, io.EOF) {
				log.Printf("⚠️  DNSTap 连接结束: %v", err)
			}
		}()
	}
}

// prepareSocketPath refuses to unlink anything that is not a socket. This
// avoids the old os.Remove(path) deleting a regular file at a user-supplied
// path (and a symlink-based attack).
func (d *DnstapReader) prepareSocketPath() error {
	dir := filepath.Dir(d.socketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建 socket 目录失败: %w", err)
	}
	fi, err := os.Lstat(d.socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("检查 socket 路径失败: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("拒绝删除非 socket 文件: %s (mode %s)", d.socketPath, fi.Mode())
	}
	// Even for a socket, verify it is stale before unlinking: dial it first.
	c, err := net.DialTimeout("unix", d.socketPath, 200*time.Millisecond)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("%s 上已有活动的 DNSTap 服务，拒绝抢占", d.socketPath)
	}
	if err := os.Remove(d.socketPath); err != nil {
		return fmt.Errorf("删除陈旧 socket 失败: %w", err)
	}
	return nil
}

func (d *DnstapReader) applySocketPerms() error {
	if err := os.Chmod(d.socketPath, d.mode); err != nil {
		return err
	}
	if d.group == "" {
		return nil
	}
	grp, err := user.LookupGroup(d.group)
	if err != nil {
		return fmt.Errorf("找不到组 %q: %w", d.group, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(d.socketPath, -1, gid); err != nil {
		return fmt.Errorf("chown socket 到组 %q 失败: %w", d.group, err)
	}
	return nil
}

func (d *DnstapReader) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	ln := d.listener
	d.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	// Unblock in-flight read deadlines so shutdown does not wait 30s.
	d.mu.Lock()
	for c := range d.conns {
		_ = c.Close()
	}
	d.mu.Unlock()
	d.wg.Wait()
	return nil
}

func (d *DnstapReader) handleConnection(conn net.Conn) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}

	ctype, contentTypes, err := readHandshakeFrame(conn)
	if err != nil {
		return fmt.Errorf("读取 READY 失败: %w", err)
	}
	if ctype != controlReady {
		return fmt.Errorf("期望 READY(0x%02x)，收到 0x%02x", controlReady, ctype)
	}
	if !hasContentType(contentTypes, contentTypeDNSTap) {
		return fmt.Errorf("不支持的 content-type %v", contentTypes)
	}
	if err := sendHandshakeFrame(conn, controlAccept, []string{contentTypeDNSTap}); err != nil {
		return fmt.Errorf("发送 ACCEPT 失败: %w", err)
	}
	ctype, _, err = readHandshakeFrame(conn)
	if err != nil {
		return fmt.Errorf("读取 START 失败: %w", err)
	}
	if ctype != controlStart {
		return fmt.Errorf("期望 START(0x%02x)，收到 0x%02x", controlStart, ctype)
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	log.Printf("📥 DNSTap 握手完成，开始接收数据帧")

	for {
		var frameLen uint32
		if err := binary.Read(conn, binary.BigEndian, &frameLen); err != nil {
			return err
		}
		if frameLen == 0 {
			ctrlType, _, err := readCtrlBody(conn)
			if err != nil {
				return fmt.Errorf("读取控制帧失败: %w", err)
			}
			if ctrlType == controlStop {
				_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
				return sendHandshakeFrame(conn, controlFinish, nil)
			}
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
			continue
		}
		if frameLen > dataFrameMaxLen {
			core.Metrics.FramesMalformed.Add(1)
			return fmt.Errorf("数据帧长度 %d 超过上限 %d", frameLen, dataFrameMaxLen)
		}
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(conn, frame); err != nil {
			return fmt.Errorf("读取数据帧失败: %w", err)
		}
		core.Metrics.FramesReceived.Add(1)
		d.processFrame(frame)
	}
}

func (d *DnstapReader) processFrame(frame []byte) {
	decoded, err := DecodeDnstapFrame(frame)
	if err != nil {
		core.Metrics.FramesMalformed.Add(1)
		return
	}
	rec, ok := d.edge.Prepare(decoded.Record)
	if !ok {
		return
	}
	decoded.Record = rec
	// The frame was already normalized/filtered/anonymized by Prepare above;
	// the merged record inherits those fields. Do not Prepare twice (it would
	// hash the IP a second time).
	if merged, complete := d.merger.Add(decoded); complete {
		d.edge.Emit(merged)
	}
}

// FlushTimeouts emits queries whose response never arrived.
func (d *DnstapReader) FlushTimeouts() {
	for _, rec := range d.merger.Expired() {
		d.edge.Emit(rec)
	}
}

func hasContentType(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func sendHandshakeFrame(w io.Writer, frameType uint32, contentTypes []string) error {
	var ctrl []byte
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, frameType)
	ctrl = append(ctrl, b...)
	for _, ct := range contentTypes {
		binary.BigEndian.PutUint32(b, controlFieldContentType)
		ctrl = append(ctrl, b...)
		binary.BigEndian.PutUint32(b, uint32(len(ct)))
		ctrl = append(ctrl, b...)
		ctrl = append(ctrl, []byte(ct)...)
	}
	frame := make([]byte, 4, 8+len(ctrl)) // escape=0
	binary.BigEndian.PutUint32(frame[0:4], 0)
	binary.BigEndian.PutUint32(b, uint32(len(ctrl)))
	frame = append(frame, b...)
	frame = append(frame, ctrl...)
	_, err := w.Write(frame)
	return err
}

func readHandshakeFrame(r io.Reader) (uint32, []string, error) {
	var escape uint32
	if err := binary.Read(r, binary.BigEndian, &escape); err != nil {
		return 0, nil, fmt.Errorf("读取 escape 失败: %w", err)
	}
	if escape != 0 {
		return 0, nil, fmt.Errorf("escape 不是 0: %d", escape)
	}
	return readCtrlBody(r)
}

func readCtrlBody(r io.Reader) (uint32, []string, error) {
	var ctrlLen uint32
	if err := binary.Read(r, binary.BigEndian, &ctrlLen); err != nil {
		return 0, nil, fmt.Errorf("读取控制帧长度失败: %w", err)
	}
	if ctrlLen < 4 || ctrlLen > controlFrameMaxLen {
		return 0, nil, fmt.Errorf("控制帧长度 %d 越界 (4..%d)", ctrlLen, controlFrameMaxLen)
	}
	ctrlData := make([]byte, ctrlLen)
	if _, err := io.ReadFull(r, ctrlData); err != nil {
		return 0, nil, fmt.Errorf("读取控制帧数据失败: %w", err)
	}
	ctrlType := binary.BigEndian.Uint32(ctrlData[0:4])
	var contentTypes []string
	off := 4
	for off+8 <= len(ctrlData) {
		fieldType := binary.BigEndian.Uint32(ctrlData[off : off+4])
		off += 4
		if fieldType != controlFieldContentType {
			break
		}
		fieldLen := binary.BigEndian.Uint32(ctrlData[off : off+4])
		off += 4
		if uint64(off)+uint64(fieldLen) > uint64(len(ctrlData)) {
			break
		}
		contentTypes = append(contentTypes, string(ctrlData[off:off+int(fieldLen)]))
		off += int(fieldLen)
	}
	return ctrlType, contentTypes, nil
}

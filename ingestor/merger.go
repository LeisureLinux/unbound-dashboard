// Package ingestor: an LRU query/response merger.
//
// Unbound's dnstap emits CLIENT_QUERY and CLIENT_RESPONSE as separate frames
// for the same transaction. The old code inserted twice (or dropped one via
// the UNIQUE constraint) and never correlated them. This merger emits exactly
// one record per transaction, with real latency when both halves arrive.
package ingestor

import (
	"container/list"
	"sync"
	"time"

	"unbound-dashboard/core"
)

// mergerKey identifies a DNS transaction as closely as dnstap allows.
// Unbound's response frames usually omit query_address/query_port, so the
// key is (dns-id, qname, qtype, clientIP).
type mergerKey struct {
	id       uint16
	domain   string
	qtype    string
	clientIP string
}

type mergerEntry struct {
	key   mergerKey
	query *DecodedFrame
	reply *DecodedFrame
	last  time.Time
}

// Merger correlates query and response frames with a bounded LRU cache.
type Merger struct {
	mu      sync.Mutex
	ll      *list.List
	items   map[mergerKey]*list.Element
	cap     int
	ttl     time.Duration
	allow   map[string]bool
	onFrame func(DecodedFrame) // unmatched query fallback
	lastGC  time.Time
}

func NewMerger(capacity int, ttl time.Duration, allowedTypes map[string]bool) *Merger {
	if capacity < 16 {
		capacity = 16
	}
	return &Merger{
		ll:     list.New(),
		items:  make(map[mergerKey]*list.Element, capacity),
		cap:    capacity,
		ttl:    ttl,
		allow:  allowedTypes,
		lastGC: time.Now(),
	}
}

// Add consumes a frame and returns at most one completed record.
// Frames whose message type is not in the allow-list are discarded (the
// equivalent of DNS-collector's traffic-filtering transformer).
func (m *Merger) Add(f DecodedFrame) (core.QueryRecord, bool) {
	if !m.allow[f.TypeName] {
		return core.QueryRecord{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	key := mergerKey{id: f.DNSID, domain: f.Record.Domain, qtype: f.Record.QType,
		clientIP: f.Record.ClientIP}
	el := m.items[key]
	if el == nil {
		e := &mergerEntry{key: key, last: time.Now()}
		if f.IsReply {
			e.reply = &f
		} else {
			e.query = &f
		}
		m.items[key] = m.ll.PushFront(e)
		m.evictLocked()
		return core.QueryRecord{}, false
	}
	e := el.Value.(*mergerEntry)
	e.last = time.Now()
	m.ll.MoveToFront(el)
	if f.IsReply {
		e.reply = &f
	} else {
		e.query = &f
	}

	if e.query != nil && e.reply != nil {
		rec := merge(*e.query, *e.reply)
		m.removeLocked(key)
		return rec, true
	}
	return core.QueryRecord{}, false
}

// Expired returns unmatched queries whose partner never arrived (timeouts).
// Call it periodically; those queries are still worth counting.
func (m *Merger) Expired() []core.QueryRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var out []core.QueryRecord
	for el := m.ll.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*mergerEntry)
		if now.Sub(e.last) < m.ttl {
			break
		}
		if e.query != nil && e.reply == nil {
			q := *e.query
			q.Record.RCode = "TIMEOUT"
			out = append(out, q.Record)
		} else if e.reply != nil && e.query == nil {
			out = append(out, e.reply.Record)
		}
		m.removeElementLocked(el)
		el = prev
	}
	return out
}

func (m *Merger) evictLocked() {
	for m.ll.Len() > m.cap {
		el := m.ll.Back()
		if el == nil {
			return
		}
		e := el.Value.(*mergerEntry)
		// An orphaned reply is still a valid observation; emit it via the
		// fallback hook instead of silently losing it.
		if e.reply != nil && e.query == nil && m.onFrame != nil {
			m.onFrame(*e.reply)
		}
		delete(m.items, e.key)
		m.ll.Remove(el)
	}
}

func (m *Merger) removeLocked(key mergerKey) {
	if el := m.items[key]; el != nil {
		m.removeElementLocked(el)
	}
}

func (m *Merger) removeElementLocked(el *list.Element) {
	delete(m.items, el.Value.(*mergerEntry).key)
	m.ll.Remove(el)
}

func merge(q, r DecodedFrame) core.QueryRecord {
	rec := r.Record
	rec.Operation = r.TypeName
	if q.Record.ClientIP != "" {
		rec.ClientIP = q.Record.ClientIP
	}
	if q.Record.Identity != "" {
		rec.Identity = q.Record.Identity
	}
	if r.Record.Domain == "" {
		rec.Domain = q.Record.Domain
	}
	if r.Record.QType == "" {
		rec.QType = q.Record.QType
	}
	if q.Record.BlockReason != "" {
		rec.BlockReason = q.Record.BlockReason
	}
	if q.QueryTime > 0 && r.RespTime > 0 && r.RespTime >= q.QueryTime {
		rec.LatencyMS = (r.RespTime - q.QueryTime) * 1000
	}
	rec.DNSSECStatus = r.Record.DNSSECStatus
	rec.Count = 1
	return rec
}

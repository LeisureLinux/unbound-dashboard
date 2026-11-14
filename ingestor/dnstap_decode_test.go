package ingestor

import (
	"testing"

	"unbound-dashboard/core"
	"unbound-dashboard/ingestor/dnspacket"
	"unbound-dashboard/ingestor/protobuf"
)

var _ = dnspacket.RCodeName // keep decoder linked in this test binary

func encVarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbField(num, wire int, payload []byte) []byte {
	b := encVarint(uint64(num<<3 | wire))
	if wire == 2 {
		b = append(b, encVarint(uint64(len(payload)))...)
	}
	return append(b, payload...)
}

// buildDnstapFrame builds a real dnstap.Dnstap protobuf payload.
func buildDnstapFrame(msgType uint64, dnsWire []byte, withResponse bool, qSec, rSec uint64) []byte {
	var msg []byte
	msg = append(msg, pbField(msgFieldType, 0, encVarint(msgType))...)
	msg = append(msg, pbField(msgFieldSocketFamily, 0, encVarint(1))...)
	msg = append(msg, pbField(msgFieldQueryAddress, 2, []byte{192, 0, 2, 55})...)
	msg = append(msg, pbField(msgFieldQueryTimeSec, 0, encVarint(qSec))...)
	msg = append(msg, pbField(msgFieldQueryTimeNSec, 5, []byte{0, 0, 0, 0})...)
	if withResponse {
		msg = append(msg, pbField(msgFieldResponseMessage, 2, dnsWire)...)
		msg = append(msg, pbField(msgFieldRespTimeSec, 0, encVarint(rSec))...)
	} else {
		msg = append(msg, pbField(msgFieldQueryMessage, 2, dnsWire)...)
	}
	top := pbField(dnstapFieldIdentity, 2, []byte("resolver-1"))
	top = append(top, pbField(dnstapFieldMessage, 2, msg)...)
	top = append(top, pbField(dnstapFieldType, 0, encVarint(1))...)
	return top
}

func dnsQueryWire(domain string) []byte {
	b := make([]byte, 12)
	b[0], b[1] = 0xAB, 0xCD
	b[5] = 1 // qdcount=1
	for _, label := range splitLabels(domain) {
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}

func splitLabels(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func TestDecodeDnstapFrame_Envelope(t *testing.T) {
	frame := buildDnstapFrame(msgClientResponse, dnsQueryWire("Example.COM"), true, 1700000000, 1700000001)
	got, err := DecodeDnstapFrame(frame)
	if err != nil {
		t.Fatalf("DecodeDnstapFrame: %v", err)
	}
	if got.Record.Identity != "resolver-1" {
		t.Errorf("identity = %q", got.Record.Identity)
	}
	if got.Record.ClientIP != "192.0.2.55" {
		t.Errorf("client IP = %q", got.Record.ClientIP)
	}
	if got.Record.Domain != "example.com" {
		t.Errorf("domain = %q", got.Record.Domain)
	}
	if got.TypeName != "CLIENT_RESPONSE" || !got.IsReply {
		t.Errorf("type=%s reply=%v", got.TypeName, got.IsReply)
	}
	if got.Record.Timestamp != 1700000001 {
		t.Errorf("timestamp = %v, want wire response time", got.Record.Timestamp)
	}
	if got.Record.LatencyMS != 1000 {
		t.Errorf("latency = %v ms", got.Record.LatencyMS)
	}
}

func TestDecodeDnstapFrame_RejectsGarbage(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0x0A, 0x05, 'x'}, // truncated message field
		pbField(dnstapFieldType, 0, encVarint(1)), // no message
	} {
		if _, err := DecodeDnstapFrame(data); err == nil {
			t.Errorf("expected error for %x", data)
		}
	}
}

func TestParseMessageTypes(t *testing.T) {
	set, err := ParseMessageTypes("client_query, CLIENT_RESPONSE")
	if err != nil || !set["CLIENT_QUERY"] || !set["CLIENT_RESPONSE"] {
		t.Fatalf("set=%v err=%v", set, err)
	}
	if _, err := ParseMessageTypes("BOGUS"); err == nil {
		t.Fatal("expected error for unknown type")
	}
	if _, err := ParseMessageTypes(""); err == nil {
		t.Fatal("expected error for empty spec")
	}
}

func TestMerger_CorrelatesQueryResponse(t *testing.T) {
	allowed, _ := ParseMessageTypes("CLIENT_QUERY,CLIENT_RESPONSE")
	m := NewMerger(16, 10*1e9, allowed)
	q, err := DecodeDnstapFrame(buildDnstapFrame(msgClientQuery, dnsQueryWire("a.test"), false, 100, 0))
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeDnstapFrame(buildDnstapFrame(msgClientResponse, dnsQueryWire("a.test"), true, 100, 101))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Add(q); ok {
		t.Fatal("query alone must not emit a record")
	}
	rec, ok := m.Add(r)
	if !ok {
		t.Fatal("merged record not emitted")
	}
	if rec.Operation != "CLIENT_RESPONSE" || rec.LatencyMS != 1000 {
		t.Errorf("operation=%q latency=%v", rec.Operation, rec.LatencyMS)
	}
	if rec.Count != 1 {
		t.Errorf("count=%d", rec.Count)
	}
}

func TestMerger_FiltersDisallowedTypes(t *testing.T) {
	allowed, _ := ParseMessageTypes("CLIENT_QUERY,CLIENT_RESPONSE")
	m := NewMerger(16, 10*1e9, allowed)
	f, _ := DecodeDnstapFrame(buildDnstapFrame(msgResolverQuery, dnsQueryWire("a.test"), false, 100, 0))
	if _, ok := m.Add(f); ok {
		t.Fatal("RESOLVER_QUERY should be filtered out")
	}
	if len(m.items) != 0 {
		t.Fatalf("filtered frame polluted the merger: %d entries", len(m.items))
	}
}

func TestEdge_NormalizeFilterAnonymize(t *testing.T) {
	var got []core.QueryRecord
	cfg := &core.Config{IgnoreDomains: "arpa, .internal", AnonymizeIP: true}
	edge := NewEdge(core.FuncSink{Fn: func(r core.QueryRecord) { got = append(got, r) }}, cfg,
		map[string]bool{"REFUSED": true})
	rec, ok := edge.Prepare(core.QueryRecord{Domain: "Example.COM.", RCode: "REFUSED"})
	if !ok {
		t.Fatal("record should not be filtered")
	}
	edge.Emit(rec)
	if len(got) != 1 || got[0].Domain != "example.com" || !got[0].Blocked {
		t.Fatalf("got %+v", got)
	}
	if got[0].BlockReason != "REFUSED" {
		t.Errorf("block reason = %q", got[0].BlockReason)
	}
	ignored, ok := edge.Prepare(core.QueryRecord{Domain: "x.internal"})
	if ok || ignored.Domain != "x.internal" {
		t.Errorf("internal domain not filtered: ok=%v", ok)
	}
	private, ok := edge.Prepare(core.QueryRecord{Domain: "good.test", ClientIP: "192.0.2.1"})
	if !ok || private.ClientIP == "192.0.2.1" || private.ClientIP[:5] != "anon-" {
		t.Errorf("IP not anonymized: %q", private.ClientIP)
	}
}

func TestBlockPolicy(t *testing.T) {
	codes, err := core.ParseBlockRCodes("NXDOMAIN,REFUSED")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rcode   string
		blocked bool
	}{
		{"NOERROR", false}, {"SERVFAIL", false},
		{"NXDOMAIN", true}, {"REFUSED", true},
	} {
		blocked, _ := core.BlockedByPolicy(core.QueryRecord{RCode: tc.rcode}, codes)
		if blocked != tc.blocked {
			t.Errorf("%s: blocked=%v want %v", tc.rcode, blocked, tc.blocked)
		}
	}
	if blocked, reason := core.BlockedByPolicy(core.QueryRecord{BlockReason: "RPZ"}, map[string]bool{}); !blocked || reason != "RPZ" {
		t.Errorf("explicit policy ignored: %v %q", blocked, reason)
	}
}

// Ensure the protobuf helper is exercised against a real dnstap frame that
// contains a policy field (an actual block signal, unlike NXDOMAIN).
func TestDecodeDnstapFrame_Policy(t *testing.T) {
	msg := pbField(msgFieldType, 0, encVarint(msgClientResponse))
	msg = append(msg, pbField(msgFieldResponseMessage, 2, dnsQueryWire("bad.test"))...)
	policy := pbField(1, 2, []byte("RPZ"))
	policy = append(policy, pbField(2, 2, []byte("blocklist"))...)
	msg = append(msg, pbField(msgFieldPolicy, 2, policy)...)
	top := pbField(dnstapFieldMessage, 2, msg)
	got, err := DecodeDnstapFrame(top)
	if err != nil {
		t.Fatal(err)
	}
	if got.Record.BlockReason != "RPZ:blocklist" {
		t.Errorf("block reason = %q", got.Record.BlockReason)
	}
	_ = protobuf.MaxVarintBytes
}

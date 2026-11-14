package dnspacket

import (
	"encoding/binary"
	"strings"
	"testing"
)

func put16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// buildPacket creates a minimal DNS response with one A answer.
func buildPacket(qname string, qtype, rcode uint16, answer string, qr bool) []byte {
	b := make([]byte, 12)
	flags := rcode
	if qr {
		flags |= 0x8000 | 0x0080
	}
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], 1)
	if answer != "" {
		binary.BigEndian.PutUint16(b[6:8], 1)
	}
	for _, label := range strings.Split(qname, ".") {
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0)
	b = put16(b, qtype)
	b = put16(b, 1)
	if answer != "" {
		b = append(b, 0xC0, 0x0C)  // pointer to qname
		b = put16(b, 1)            // A
		b = put16(b, 1)            // IN
		b = append(b, 0, 0, 0, 60) // ttl
		b = put16(b, 4)
		b = append(b, []byte{93, 184, 216, 34}...)
	}
	return b
}

func TestParse_Response(t *testing.T) {
	pkt := buildPacket("Example.COM", 1, 3, "93.184.216.34", true)
	m, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.QName != "Example.COM" || m.QType != "A" || m.QClass != "IN" {
		t.Errorf("question = %q %q %q", m.QName, m.QType, m.QClass)
	}
	if m.RCode != "NXDOMAIN" || !m.IsReply || !m.Flags.RA {
		t.Errorf("rcode=%s reply=%v ra=%v", m.RCode, m.IsReply, m.Flags.RA)
	}
	if len(m.Answers) != 1 || m.Answers[0] != "93.184.216.34" {
		t.Errorf("answers = %v", m.Answers)
	}
	if m.ID != 0x1234 {
		t.Errorf("id = %d", m.ID)
	}
}

func TestParse_QueryAndTypes(t *testing.T) {
	for qtype, want := range map[uint16]string{1: "A", 28: "AAAA", 65: "HTTPS", 257: "CAA", 999: "TYPE999"} {
		m, err := Parse(buildPacket("a.test", qtype, 0, "", false))
		if err != nil {
			t.Fatal(err)
		}
		if m.QType != want || m.IsReply {
			t.Errorf("qtype %d -> %q (want %q), reply=%v", qtype, m.QType, want, m.IsReply)
		}
	}
}

func TestParse_RCodeNames(t *testing.T) {
	for code, want := range map[uint16]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"} {
		m, err := Parse(buildPacket("x.test", 1, code, "", true))
		if err != nil {
			t.Fatal(err)
		}
		if m.RCode != want {
			t.Errorf("rcode %d = %q, want %q", code, m.RCode, want)
		}
	}
}

func TestParse_Bounds(t *testing.T) {
	for _, data := range [][]byte{
		{}, {1, 2, 3},
		buildPacket("x.test", 1, 0, "", false)[:13], // truncated question
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("expected error for %d bytes", len(data))
		}
	}
}

func TestDecodeName_CompressionLoopDoesNotHang(t *testing.T) {
	// 0xC0 0x0C at offset 12 points back to itself.
	b := make([]byte, 14)
	b[12], b[13] = 0xC0, 0x0C
	if _, _, err := DecodeName(b, 12); err == nil {
		t.Fatal("expected cyclic pointer error")
	}
}

func TestDecodeName_Truncated(t *testing.T) {
	for _, b := range [][]byte{{3, 'a'}, {0xC0}, {0x40, 0, 0, 0, 0}} {
		if _, _, err := DecodeName(b, 0); err == nil {
			t.Errorf("expected error for %x", b)
		}
	}
}

func TestDecodeName_ValidPointer(t *testing.T) {
	b := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xC0, 0x00}
	name, next, err := DecodeName(b, 17)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.example.com" {
		t.Errorf("name = %q", name)
	}
	if next != 19 {
		t.Errorf("next = %d, want 19", next)
	}
}

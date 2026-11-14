package protobuf

import (
	"encoding/binary"
	"testing"
)

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func TestFields_RoundTrip(t *testing.T) {
	b := []byte{}
	b = appendVarint(b, 14<<3|2) // field 14, length-delimited
	b = appendVarint(b, 5)
	b = append(b, []byte("hello")...)
	b = appendVarint(b, 15<<3|0) // field 15, varint
	b = appendVarint(b, 300)
	b = appendVarint(b, 9<<3|5) // field 9, fixed32
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, 123456)
	b = append(b, tmp...)

	fields, err := Fields(b)
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if len(fields) != 3 {
		t.Fatalf("got %d fields, want 3", len(fields))
	}
	if got := string(BytesField(fields, 14)); got != "hello" {
		t.Errorf("BytesField(14) = %q", got)
	}
	if v, ok := VarintField(fields, 15); !ok || v != 300 {
		t.Errorf("VarintField(15) = %d,%v", v, ok)
	}
	if v, ok := Fixed32Field(fields, 9); !ok || v != 123456 {
		t.Errorf("Fixed32Field(9) = %d,%v", v, ok)
	}
}

func TestFields_RejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"truncated length":     {14<<3 | 2, 10, 'x'},
		"truncated varint":     {0x80},
		"truncated fixed32":    {9<<3 | 5, 1, 2},
		"truncated fixed64":    {9<<3 | 1, 1, 2},
		"unsupported wiretype": {1<<3 | 3},
		"field zero":           {0x02, 0x00},
		"varint overflow":      {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Fields(data); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestVarint(t *testing.T) {
	for _, want := range []uint64{0, 1, 127, 128, 300, 1 << 32, ^uint64(0)} {
		b := appendVarint(nil, want)
		got, n := Varint(b)
		if got != want || n != len(b) {
			t.Errorf("Varint(%x) = %d,%d; want %d,%d", b, got, n, want, len(b))
		}
	}
}

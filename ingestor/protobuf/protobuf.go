// Package protobuf implements the tiny subset of the Protocol Buffers wire
// format needed to decode DNSTap envelopes. Keeping it dependency-free lets
// the project stay a single static binary; the cost is that we must be
// strict about bounds (untrusted network data).
package protobuf

import (
	"encoding/binary"
	"fmt"
)

// MaxVarintBytes is the maximum length of a uint64 varint.
const MaxVarintBytes = 10

// Field is one decoded protobuf field. For wire type 2, Bytes points into
// the original buffer (no copy). For wire type 5 it is the 4 raw bytes.
type Field struct {
	Number int
	Wire   int
	Varint uint64
	Bytes  []byte
}

// Fields walks a serialized message and returns its fields. It returns an
// error on malformed input rather than panicking.
func Fields(data []byte) ([]Field, error) {
	var out []Field
	for off := 0; off < len(data); {
		tag, n := Varint(data[off:])
		if n == 0 {
			return nil, fmt.Errorf("truncated varint at offset %d", off)
		}
		off += n
		num := int(tag >> 3)
		wire := int(tag & 0x07)
		if num == 0 {
			return nil, fmt.Errorf("invalid field number 0 at offset %d", off-n)
		}
		field := Field{Number: num, Wire: wire}
		switch wire {
		case 0: // varint
			v, k := Varint(data[off:])
			if k == 0 {
				return nil, fmt.Errorf("truncated varint value for field %d", num)
			}
			field.Varint = v
			off += k
		case 1: // 64-bit
			if off+8 > len(data) {
				return nil, fmt.Errorf("truncated fixed64 for field %d", num)
			}
			field.Bytes = data[off : off+8]
			off += 8
		case 2: // length-delimited
			l, k := Varint(data[off:])
			if k == 0 {
				return nil, fmt.Errorf("truncated length for field %d", num)
			}
			off += k
			if l > uint64(len(data)-off) {
				return nil, fmt.Errorf("field %d length %d exceeds buffer %d", num, l, len(data)-off)
			}
			field.Bytes = data[off : off+int(l)]
			off += int(l)
		case 5: // 32-bit
			if off+4 > len(data) {
				return nil, fmt.Errorf("truncated fixed32 for field %d", num)
			}
			field.Bytes = data[off : off+4]
			off += 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d for field %d", wire, num)
		}
		out = append(out, field)
	}
	return out, nil
}

// BytesField returns the first length-delimited field with the given number.
func BytesField(fields []Field, num int) []byte {
	for _, f := range fields {
		if f.Number == num && f.Wire == 2 {
			return f.Bytes
		}
	}
	return nil
}

// VarintField returns the first varint field with the given number.
func VarintField(fields []Field, num int) (uint64, bool) {
	for _, f := range fields {
		if f.Number == num && f.Wire == 0 {
			return f.Varint, true
		}
	}
	return 0, false
}

// Fixed32Field returns the first fixed32 field with the given number.
func Fixed32Field(fields []Field, num int) (uint32, bool) {
	for _, f := range fields {
		if f.Number == num && f.Wire == 5 && len(f.Bytes) == 4 {
			return binary.LittleEndian.Uint32(f.Bytes), true
		}
	}
	return 0, false
}

// Varint decodes one unsigned varint. It returns (0, 0) on overflow/truncation.
func Varint(data []byte) (uint64, int) {
	var val uint64
	for i := 0; i < len(data) && i < MaxVarintBytes; i++ {
		b := data[i]
		if i == MaxVarintBytes-1 && b > 1 {
			return 0, 0 // would overflow uint64
		}
		val |= uint64(b&0x7F) << (7 * uint(i))
		if b&0x80 == 0 {
			return val, i + 1
		}
	}
	return 0, 0
}

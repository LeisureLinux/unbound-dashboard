// Package dnspacket decodes the parts of an RFC 1035 DNS message that a
// dashboard needs: the question, the rcode, DNS flags and the first answer.
// All parsing is bounds-checked (frames come from the network).
package dnspacket

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	maxNameLength = 255
	maxPointers   = 32 // guard against cyclic compression pointers
)

// Message is the decoded, dashboard-relevant view of a DNS packet.
type Message struct {
	ID          uint16
	QName       string
	QType       string
	QClass      string
	RCode       string
	Flags       Flags
	QDCount     uint16
	ANCount     uint16
	Answers     []string // A/AAAA answers (up to 8)
	IsReply     bool
	EDNSDO      bool // EDNS DNSSEC OK bit
	EDNSUDPSize uint16
}

type Flags struct {
	QR, AA, TC, RD, RA, AD, CD bool
}

// Parse decodes a wire-format DNS message.
func Parse(data []byte) (Message, error) {
	var m Message
	if len(data) < 12 {
		return m, fmt.Errorf("DNS header too short: %d bytes", len(data))
	}
	m.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	m.Flags = Flags{
		QR: flags&0x8000 != 0, AA: flags&0x4000 != 0, TC: flags&0x0200 != 0,
		RD: flags&0x0100 != 0, RA: flags&0x0080 != 0,
		AD: flags&0x0020 != 0, CD: flags&0x0010 != 0,
	}
	m.IsReply = m.Flags.QR
	m.RCode = RCodeName(int(flags & 0x0F))
	m.QDCount = binary.BigEndian.Uint16(data[4:6])
	m.ANCount = binary.BigEndian.Uint16(data[6:8])
	nsCount := binary.BigEndian.Uint16(data[8:10])
	arCount := binary.BigEndian.Uint16(data[10:12])

	off := 12
	if m.QDCount > 0 {
		name, next, err := DecodeName(data, off)
		if err != nil {
			return m, err
		}
		off = next
		if off+4 > len(data) {
			return m, fmt.Errorf("truncated question section")
		}
		m.QName = name
		m.QType = QTypeName(binary.BigEndian.Uint16(data[off : off+2]))
		m.QClass = ClassName(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
	} else {
		// A response with no question is still useful for rcode stats, but
		// it cannot be attributed to a domain.
		return m, nil
	}

	// Skip the remaining questions, then parse answers.
	for i := uint16(1); i < m.QDCount; i++ {
		_, next, err := DecodeName(data, off)
		if err != nil {
			return m, err
		}
		off = next + 4
		if off > len(data) {
			return m, fmt.Errorf("truncated question section")
		}
	}

	parseRR := func(extract bool) (int, error) {
		_, next, err := DecodeName(data, off)
		if err != nil {
			return 0, err
		}
		off = next
		if off+10 > len(data) {
			return 0, fmt.Errorf("truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(data[off : off+2])
		rclass := binary.BigEndian.Uint16(data[off+2 : off+4])
		rdlen := int(binary.BigEndian.Uint16(data[off+8 : off+10]))
		off += 10
		if off+rdlen > len(data) {
			return 0, fmt.Errorf("truncated RDATA")
		}
		if extract && rclass == 1 && (rtype == 1 || rtype == 28) && rdlen >= 4 {
			rdata := data[off : off+rdlen]
			if len(m.Answers) < 8 {
				if rtype == 1 && rdlen == 4 {
					m.Answers = append(m.Answers, ipString(rdata[:4]))
				} else if rtype == 28 && rdlen == 16 {
					m.Answers = append(m.Answers, ipString(rdata[:16]))
				}
			}
		}
		// EDNS0 OPT record lives in the additional section.
		if extract && rtype == 41 {
			ttl := binary.BigEndian.Uint32(data[off-6 : off-2])
			m.EDNSDO = ttl&0x8000 != 0
			m.EDNSUDPSize = rclass
		}
		off += rdlen
		return off, nil
	}

	for i := uint16(0); i < m.ANCount; i++ {
		n, err := parseRR(true)
		if err != nil {
			return m, err
		}
		off = n
	}
	for i := uint16(0); i < nsCount; i++ {
		n, err := parseRR(false)
		if err != nil {
			return m, err
		}
		off = n
	}
	for i := uint16(0); i < arCount; i++ {
		n, err := parseRR(true)
		if err != nil {
			return m, err
		}
		off = n
	}
	return m, nil
}

func ipString(b []byte) string {
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	if len(b) == 16 {
		parts := make([]string, 8)
		for i := range parts {
			parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(b[i*2:i*2+2]))
		}
		return strings.Join(parts, ":")
	}
	return ""
}

// DecodeName decodes a possibly compressed DNS name. It follows compression
// pointers with a hard limit so a crafted cyclic pointer cannot hang us.
func DecodeName(data []byte, offset int) (string, int, error) {
	var parts []string
	cur := offset
	returnOffset := offset
	jumped := false
	total := 0
	visited := 0

	for {
		if cur >= len(data) {
			return "", 0, fmt.Errorf("name offset %d out of range", cur)
		}
		length := int(data[cur])
		switch {
		case length == 0:
			cur++
			if jumped {
				return join(parts), returnOffset, nil
			}
			return join(parts), cur, nil
		case length&0xC0 == 0xC0:
			if cur+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated compression pointer")
			}
			visited++
			if visited > maxPointers {
				return "", 0, fmt.Errorf("too many compression pointers (possible loop)")
			}
			ptr := int(binary.BigEndian.Uint16(data[cur:cur+2]) & 0x3FFF)
			if ptr >= len(data) {
				return "", 0, fmt.Errorf("compression pointer %d out of range", ptr)
			}
			if !jumped {
				returnOffset = cur + 2
				jumped = true
			}
			cur = ptr
		case length&0xC0 != 0:
			return "", 0, fmt.Errorf("reserved label length 0x%02x", length)
		default:
			cur++
			if cur+length > len(data) {
				return "", 0, fmt.Errorf("label exceeds packet")
			}
			total += length + 1
			if total > maxNameLength {
				return "", 0, fmt.Errorf("DNS name exceeds %d bytes", maxNameLength)
			}
			parts = append(parts, string(data[cur:cur+length]))
			cur += length
		}
	}
}

func join(parts []string) string { return strings.Join(parts, ".") }

func RCodeName(rcode int) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	case 7:
		return "YXRRSET"
	case 8:
		return "NXRRSET"
	case 9:
		return "NOTAUTH"
	case 10:
		return "NOTZONE"
	case 16:
		return "BADVERS"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func QTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 3:
		return "MD"
	case 4:
		return "MF"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 7:
		return "MB"
	case 8:
		return "MG"
	case 9:
		return "MR"
	case 10:
		return "NULL"
	case 12:
		return "PTR"
	case 13:
		return "HINFO"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 17:
		return "RP"
	case 24:
		return "SIG"
	case 25:
		return "KEY"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 36:
		return "KX"
	case 37:
		return "CERT"
	case 39:
		return "DNAME"
	case 41:
		return "OPT"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 48:
		return "DNSKEY"
	case 50:
		return "NSEC3"
	case 52:
		return "TLSA"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 99:
		return "SPF"
	case 255:
		return "ANY"
	case 257:
		return "CAA"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

func ClassName(class uint16) string {
	switch class {
	case 1:
		return "IN"
	case 2:
		return "CS"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", class)
	}
}

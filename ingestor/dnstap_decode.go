// Package ingestor: DNSTap protobuf decoding.
package ingestor

import (
	"fmt"
	"net"
	"strings"
	"time"

	"unbound-dashboard/core"
	"unbound-dashboard/ingestor/dnspacket"
	"unbound-dashboard/ingestor/protobuf"
)

// dnstap.proto field numbers.
const (
	dnstapFieldIdentity = 1
	dnstapFieldVersion  = 2
	dnstapFieldExtra    = 3
	dnstapFieldMessage  = 14
	dnstapFieldType     = 15

	msgFieldType            = 1
	msgFieldSocketFamily    = 2
	msgFieldSocketProtocol  = 3
	msgFieldQueryAddress    = 4
	msgFieldResponseAddress = 5
	msgFieldQueryPort       = 6
	msgFieldResponsePort    = 7
	msgFieldQueryTimeSec    = 8
	msgFieldQueryTimeNSec   = 9
	msgFieldQueryMessage    = 10
	msgFieldRespTimeSec     = 12
	msgFieldRespTimeNSec    = 13
	msgFieldResponseMessage = 14
	msgFieldPolicy          = 15
)

// MessageType constants from dnstap.proto.
const (
	msgAuthQuery      = 1
	msgAuthResponse   = 2
	msgResolverQuery  = 3
	msgResolverResp   = 4
	msgClientQuery    = 5
	msgClientResponse = 6
	msgForwarderQuery = 7
	msgForwarderResp  = 8
	msgStubQuery      = 9
	msgStubResponse   = 10
	msgToolQuery      = 11
	msgToolResponse   = 12
	msgUpdateQuery    = 13
	msgUpdateResponse = 14
)

var messageTypeNames = map[uint64]string{
	msgAuthQuery: "AUTH_QUERY", msgAuthResponse: "AUTH_RESPONSE",
	msgResolverQuery: "RESOLVER_QUERY", msgResolverResp: "RESOLVER_RESPONSE",
	msgClientQuery: "CLIENT_QUERY", msgClientResponse: "CLIENT_RESPONSE",
	msgForwarderQuery: "FORWARDER_QUERY", msgForwarderResp: "FORWARDER_RESPONSE",
	msgStubQuery: "STUB_QUERY", msgStubResponse: "STUB_RESPONSE",
	msgToolQuery: "TOOL_QUERY", msgToolResponse: "TOOL_RESPONSE",
	msgUpdateQuery: "UPDATE_QUERY", msgUpdateResponse: "UPDATE_RESPONSE",
}

// ParseMessageTypes validates a --dnstap-types value.
func ParseMessageTypes(spec string) (map[string]bool, error) {
	set := make(map[string]bool)
	for _, s := range strings.Split(spec, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		found := false
		for _, name := range messageTypeNames {
			if name == s {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown DNSTap message type %q", s)
		}
		set[s] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("--dnstap-types must not be empty")
	}
	return set, nil
}

// DecodedFrame is the intermediate representation of one DNSTap frame.
type DecodedFrame struct {
	Record    core.QueryRecord
	DNSID     uint16
	IsReply   bool
	TypeNum   uint64
	TypeName  string
	QueryTime float64
	RespTime  float64
}

// DecodeDnstapFrame decodes a dnstap.Dnstap protobuf payload.
// nolint: gocyclo — the protobuf field walk is inherently flat.
func DecodeDnstapFrame(data []byte) (DecodedFrame, error) {
	var out DecodedFrame
	top, err := protobuf.Fields(data)
	if err != nil {
		return out, err
	}
	msgBytes := protobuf.BytesField(top, dnstapFieldMessage)
	if msgBytes == nil {
		return out, fmt.Errorf("dnstap frame has no message field")
	}
	msg, err := protobuf.Fields(msgBytes)
	if err != nil {
		return out, err
	}

	out.TypeNum, _ = protobuf.VarintField(msg, msgFieldType)
	out.TypeName = messageTypeNames[out.TypeNum]
	if out.TypeName == "" {
		out.TypeName = fmt.Sprintf("TYPE_%d", out.TypeNum)
	}
	out.Record.Operation = out.TypeName
	out.Record.Identity = string(protobuf.BytesField(top, dnstapFieldIdentity))

	// Client IP: prefer query_address (initiator), fall back to response_address.
	family, _ := protobuf.VarintField(msg, msgFieldSocketFamily)
	addrBytes := protobuf.BytesField(msg, msgFieldQueryAddress)
	if addrBytes == nil {
		addrBytes = protobuf.BytesField(msg, msgFieldResponseAddress)
	}
	out.Record.ClientIP = formatAddress(addrBytes, family)

	if sec, ok := protobuf.VarintField(msg, msgFieldQueryTimeSec); ok {
		out.QueryTime = float64(sec)
		if ns, ok := protobuf.Fixed32Field(msg, msgFieldQueryTimeNSec); ok {
			out.QueryTime += float64(ns) / 1e9
		}
	}
	if sec, ok := protobuf.VarintField(msg, msgFieldRespTimeSec); ok {
		out.RespTime = float64(sec)
		if ns, ok := protobuf.Fixed32Field(msg, msgFieldRespTimeNSec); ok {
			out.RespTime += float64(ns) / 1e9
		}
	}
	if out.RespTime > 0 && out.QueryTime > 0 && out.RespTime >= out.QueryTime {
		out.Record.LatencyMS = (out.RespTime - out.QueryTime) * 1000
	}

	// Event timestamp comes from the wire, not time.Now(). Fractional seconds
	// matter: the old integer-second timestamp caused mass deduplication.
	switch {
	case out.RespTime > 0:
		out.Record.Timestamp = out.RespTime
	case out.QueryTime > 0:
		out.Record.Timestamp = out.QueryTime
	default:
		out.Record.Timestamp = float64(time.Now().UnixNano()) / 1e9
	}

	wire := protobuf.BytesField(msg, msgFieldResponseMessage)
	out.IsReply = wire != nil
	if wire == nil {
		wire = protobuf.BytesField(msg, msgFieldQueryMessage)
	}
	if wire == nil {
		return out, fmt.Errorf("dnstap message has no DNS wire payload")
	}
	pkt, err := dnspacket.Parse(wire)
	if err != nil {
		return out, fmt.Errorf("decode DNS packet: %w", err)
	}
	if pkt.QName == "" {
		return out, fmt.Errorf("DNS packet has no question")
	}
	out.DNSID = pkt.ID
	out.IsReply = pkt.IsReply || out.IsReply
	out.Record.Domain = core.NormalizeDomain(pkt.QName)
	out.Record.QType = pkt.QType
	out.Record.RCode = pkt.RCode
	if len(pkt.Answers) > 0 {
		out.Record.Response = pkt.Answers[0]
	}
	if pkt.EDNSDO {
		out.Record.DNSSECStatus = "DO"
	}
	if pkt.Flags.AD {
		out.Record.DNSSECStatus = "AD"
	}

	// An RPZ/local-zone policy is an actual block signal, unlike NXDOMAIN.
	if policy := protobuf.BytesField(msg, msgFieldPolicy); policy != nil {
		pf, err := protobuf.Fields(policy)
		if err == nil {
			ptype := string(protobuf.BytesField(pf, 1))
			prule := string(protobuf.BytesField(pf, 2))
			if ptype == "" {
				ptype = "POLICY"
			}
			if prule != "" {
				ptype += ":" + prule
			}
			out.Record.BlockReason = ptype
		}
	}
	return out, nil
}

func formatAddress(b []byte, family uint64) string {
	if len(b) == 4 || len(b) == 16 {
		if ip := net.IP(b); ip != nil {
			return ip.String()
		}
	}
	_ = family
	return ""
}

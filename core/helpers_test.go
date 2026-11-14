package core

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.":  "example.com",
		" example.com ": "example.com",
		".":             "",
		"a.b.":          "a.b",
	} {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDomainFilter(t *testing.T) {
	f := NewDomainFilter("arpa, .internal, example.com")
	for _, in := range []string{"1.0.0.127.in-addr.arpa", "x.internal", "sub.x.internal", "example.com", "www.example.com"} {
		if !f.Ignored(in) {
			t.Errorf("%q should be ignored", in)
		}
	}
	for _, in := range []string{"example.org", "notinternal.test", "example.com.cn"} {
		if f.Ignored(in) {
			t.Errorf("%q should not be ignored", in)
		}
	}
}

func TestAnonymizer(t *testing.T) {
	a := NewAnonymizer()
	first := a.IP("192.0.2.1")
	if !strings.HasPrefix(first, "anon-") || first == "192.0.2.1" {
		t.Errorf("hash = %q", first)
	}
	if a.IP("192.0.2.1") != first {
		t.Error("hash is not stable within a process")
	}
	if a.IP("192.0.2.2") == first {
		t.Error("hash collides for different IPs")
	}
	if a.IP("") != "" {
		t.Error("empty IP should stay empty")
	}
	var nilA *Anonymizer
	if nilA.IP("1.2.3.4") != "" {
		t.Error("nil receiver should be safe")
	}
}

func TestParseBlockRCodes(t *testing.T) {
	set, err := ParseBlockRCodes("nxdomain, REFUSED")
	if err != nil || !set["NXDOMAIN"] || !set["REFUSED"] || len(set) != 2 {
		t.Fatalf("set=%v err=%v", set, err)
	}
	if set, err := ParseBlockRCodes(""); err != nil || len(set) != 0 {
		t.Errorf("empty spec = %v, %v", set, err)
	}
	if _, err := ParseBlockRCodes("WAT"); err == nil {
		t.Error("expected error for unknown rcode")
	}
}

func TestIsAnomalousRCode(t *testing.T) {
	for _, c := range []string{"NOERROR", "NXDOMAIN", ""} {
		if IsAnomalousRCode(c) {
			t.Errorf("%q should not be anomalous", c)
		}
	}
	for _, c := range []string{"SERVFAIL", "REFUSED", "FORMERR"} {
		if !IsAnomalousRCode(c) {
			t.Errorf("%q should be anomalous", c)
		}
	}
}

func TestValidate(t *testing.T) {
	base := func() *Config {
		return &Config{
			Port: 9153, DNSTapPath: "/tmp/t.sock", CacheTTLDays: 90, MaxSizeMB: 200,
			QueueSize: 4096, BatchSize: 64, FlushMS: 10,
			SocketModeStr: "0660", BlockRCodes: "NXDOMAIN,REFUSED",
			DNSTapTypes: "CLIENT_QUERY,CLIENT_RESPONSE",
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*Config){
		"both sources": func(c *Config) { c.LogFilePath = "/tmp/x.log" },
		"no source":    func(c *Config) { c.DNSTapPath = "" },
		"bad port":     func(c *Config) { c.Port = 0 },
		"bad mode":     func(c *Config) { c.SocketModeStr = "0999" },
		"bad rcode":    func(c *Config) { c.BlockRCodes = "WAT" },
		"bad type":     func(c *Config) { c.DNSTapTypes = "WAT" },
	}
	for name, mutate := range cases {
		c := base()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	c := base()
	c.SocketModeStr = "0660"
	if err := c.Validate(); err != nil || c.SocketMode != 0o660 {
		t.Errorf("socket mode parse = %v, %v", c.SocketMode, err)
	}
}

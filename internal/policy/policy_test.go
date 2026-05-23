package policy

import (
	"testing"

	"prefixcloak/internal/cloak"
)

func TestParsePolicy(t *testing.T) {
	p, err := parse([]byte(`
mode: anonymous
ipv4:
  truncate_prefix: 24
ipv6:
  preserve_bits: 32
  truncate_prefix: 48
verification:
  fail_on_raw_leak: false
`), Default())
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != cloak.ModeAnonymous {
		t.Fatalf("mode = %q", p.Mode)
	}
	if p.IPv4.TruncatePrefix != 24 || p.IPv6.PreserveBits != 32 || p.IPv6.TruncatePrefix != 48 {
		t.Fatalf("unexpected IP policy: %+v %+v", p.IPv4, p.IPv6)
	}
	if p.Verification.FailOnRawLeak {
		t.Fatal("expected fail_on_raw_leak=false")
	}
}

package cloak

import (
	"net"
	"testing"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestPrefixPreservingIPv4(t *testing.T) {
	c, err := New(testKey(), Config{Mode: ModePseudonymous})
	if err != nil {
		t.Fatal(err)
	}

	a, err := c.TransformIP(net.ParseIP("203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.TransformIP(net.ParseIP("203.0.113.200"))
	if err != nil {
		t.Fatal(err)
	}
	if commonPrefixBits(a.To4(), b.To4()) < 24 {
		t.Fatalf("mapped addresses do not preserve /24 prefix: %s %s", a, b)
	}
}

func TestAnonymousIPv4TruncatesToManyToOne(t *testing.T) {
	c, err := New(testKey(), Config{Mode: ModeAnonymous, IPv4TruncatePrefix: 24})
	if err != nil {
		t.Fatal(err)
	}

	a, err := c.TransformIP(net.ParseIP("203.0.113.10"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.TransformIP(net.ParseIP("203.0.113.200"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatalf("expected /24 truncation to collapse hosts: %s != %s", a, b)
	}
}

func TestTransformLineRejectsRawLeak(t *testing.T) {
	c, err := New(testKey(), Config{Mode: ModePseudonymous, IPv4PreserveBits: 32, FailOnRawLeak: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.TransformLine("client=192.0.2.1"); err == nil {
		t.Fatal("expected raw leak error")
	}
}

func TestTransformLineRewritesCompressedIPv6(t *testing.T) {
	c, err := New(testKey(), Config{Mode: ModePseudonymous, FailOnRawLeak: true})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.TransformLine(`client=2001:db8:10::44 "GET /"`)
	if err != nil {
		t.Fatal(err)
	}
	if out == `client=2001:db8:10::44 "GET /"` {
		t.Fatal("expected compressed IPv6 address to be rewritten")
	}
}

func commonPrefixBits(a, b net.IP) int {
	count := 0
	for i := range a {
		x := a[i] ^ b[i]
		for bit := 0; bit < 8; bit++ {
			if x&(0x80>>bit) != 0 {
				return count
			}
			count++
		}
	}
	return count
}

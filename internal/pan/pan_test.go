package pan

import (
	"net"
	"testing"
)

func TestTransformPreservesSharedPrefixIPv4(t *testing.T) {
	tp, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	a, err := tp.Transform(net.ParseIP("198.51.100.10"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := tp.Transform(net.ParseIP("198.51.100.200"))
	if err != nil {
		t.Fatal(err)
	}
	if commonPrefixBits(a.To4(), b.To4()) < 24 {
		t.Fatalf("expected mapped addresses to share at least /24: %s %s", a, b)
	}
}

func TestTransformIsDeterministic(t *testing.T) {
	tp, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	first, err := tp.Transform(net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := tp.Transform(net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatalf("expected deterministic output: %s != %s", first, second)
	}
}

func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
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

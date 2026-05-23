package cloak

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"prefixcloak/internal/pan"
)

type Mode string

const (
	ModePseudonymous Mode = "pseudonymous"
	ModeAnonymous    Mode = "anonymous"
)

type Config struct {
	Mode               Mode
	IPv4PreserveBits   int
	IPv6PreserveBits   int
	IPv4TruncatePrefix int
	IPv6TruncatePrefix int
	FailOnRawLeak      bool
}

type Cloaker struct {
	cfg Config
	pan *pan.Transformer
}

var ipTokenRE = regexp.MustCompile(`(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\[?[0-9a-f:.]*:[0-9a-f:.%]+\]?`)

func New(key []byte, cfg Config) (*Cloaker, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModePseudonymous
	}
	if cfg.Mode != ModePseudonymous && cfg.Mode != ModeAnonymous {
		return nil, fmt.Errorf("unsupported mode %q", cfg.Mode)
	}
	if cfg.Mode == ModeAnonymous {
		if cfg.IPv4TruncatePrefix == 0 {
			cfg.IPv4TruncatePrefix = 24
		}
		if cfg.IPv6TruncatePrefix == 0 {
			cfg.IPv6TruncatePrefix = 48
		}
	}
	if err := validateBits("IPv4 preserve", cfg.IPv4PreserveBits, 0, 32); err != nil {
		return nil, err
	}
	if err := validateBits("IPv6 preserve", cfg.IPv6PreserveBits, 0, 128); err != nil {
		return nil, err
	}
	if err := validateBits("IPv4 truncate prefix", cfg.IPv4TruncatePrefix, 0, 32); err != nil {
		return nil, err
	}
	if err := validateBits("IPv6 truncate prefix", cfg.IPv6TruncatePrefix, 0, 128); err != nil {
		return nil, err
	}
	transformer, err := pan.New(key)
	if err != nil {
		return nil, err
	}
	return &Cloaker{cfg: cfg, pan: transformer}, nil
}

func (c *Cloaker) TransformLine(line string) (string, error) {
	seen := map[string]struct{}{}
	out := ipTokenRE.ReplaceAllStringFunc(line, func(token string) string {
		trimmed := strings.Trim(token, "[]")
		ip := net.ParseIP(trimmed)
		if ip == nil {
			return token
		}
		seen[ip.String()] = struct{}{}
		mapped, err := c.TransformIP(ip)
		if err != nil {
			return token
		}
		if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
			return "[" + mapped.String() + "]"
		}
		return mapped.String()
	})
	if c.cfg.FailOnRawLeak {
		for raw := range seen {
			if strings.Contains(out, raw) {
				return "", fmt.Errorf("raw IP leak detected after transform: %s", raw)
			}
		}
	}
	return out, nil
}

func (c *Cloaker) TransformIP(ip net.IP) (net.IP, error) {
	if ip == nil {
		return nil, errors.New("nil IP")
	}
	mapped, err := c.pan.Transform(ip)
	if err != nil {
		return nil, err
	}

	if v4 := ip.To4(); v4 != nil {
		out := mapped.To4()
		if out == nil {
			return nil, errors.New("prefix transformer returned non-IPv4 output for IPv4 input")
		}
		out = combinePreservedPrefix(v4, out, c.cfg.IPv4PreserveBits)
		if c.cfg.Mode == ModeAnonymous && c.cfg.IPv4TruncatePrefix > 0 {
			out = truncateToPrefix(out, c.cfg.IPv4TruncatePrefix)
		}
		return out, nil
	}

	v6 := ip.To16()
	if v6 == nil {
		return nil, errors.New("invalid IP")
	}
	out := mapped.To16()
	if out == nil {
		return nil, errors.New("prefix transformer returned invalid IPv6 output")
	}
	out = combinePreservedPrefix(v6, out, c.cfg.IPv6PreserveBits)
	if c.cfg.Mode == ModeAnonymous && c.cfg.IPv6TruncatePrefix > 0 {
		out = truncateToPrefix(out, c.cfg.IPv6TruncatePrefix)
	}
	return out, nil
}

func combinePreservedPrefix(original, mapped net.IP, bits int) net.IP {
	out := append(net.IP(nil), mapped...)
	for bit := 0; bit < bits; bit++ {
		byteIdx := bit / 8
		mask := byte(0x80 >> (bit % 8))
		if original[byteIdx]&mask != 0 {
			out[byteIdx] |= mask
		} else {
			out[byteIdx] &^= mask
		}
	}
	return out
}

func truncateToPrefix(ip net.IP, prefix int) net.IP {
	out := append(net.IP(nil), ip...)
	for bit := prefix; bit < len(out)*8; bit++ {
		out[bit/8] &^= byte(0x80 >> (bit % 8))
	}
	return out
}

func validateBits(name string, value, min, max int) error {
	if value < min || value > max {
		return fmt.Errorf("%s bits out of range: got %d, want %d..%d", name, value, min, max)
	}
	return nil
}

package policy

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"prefixcloak/internal/cloak"
)

type Policy struct {
	Mode         cloak.Mode `yaml:"mode"`
	IPv4         IPPolicy   `yaml:"ipv4"`
	IPv6         IPPolicy   `yaml:"ipv6"`
	Verification Verify     `yaml:"verification"`
}

type IPPolicy struct {
	PreserveBits   int `yaml:"preserve_bits"`
	TruncatePrefix int `yaml:"truncate_prefix"`
}

type Verify struct {
	FailOnRawLeak bool `yaml:"fail_on_raw_leak"`
}

func Default() Policy {
	return Policy{
		Mode: cloak.ModePseudonymous,
		Verification: Verify{
			FailOnRawLeak: true,
		},
	}
}

func Load(path string) (Policy, error) {
	p := Default()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	return parse(data, p)
}

func (p Policy) CloakConfig() cloak.Config {
	return cloak.Config{
		Mode:               p.Mode,
		IPv4PreserveBits:   p.IPv4.PreserveBits,
		IPv6PreserveBits:   p.IPv6.PreserveBits,
		IPv4TruncatePrefix: p.IPv4.TruncatePrefix,
		IPv6TruncatePrefix: p.IPv6.TruncatePrefix,
		FailOnRawLeak:      p.Verification.FailOnRawLeak,
	}
}

func parse(data []byte, p Policy) (Policy, error) {
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := stripComment(scanner.Text())
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		key, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok {
			return p, fmt.Errorf("policy line %d: expected key: value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if indent == 0 && value == "" {
			section = key
			continue
		}
		if indent == 0 {
			section = ""
		}
		if err := applyField(&p, section, key, value); err != nil {
			return p, fmt.Errorf("policy line %d: %w", lineNo, err)
		}
	}
	return p, scanner.Err()
}

func applyField(p *Policy, section, key, value string) error {
	switch section {
	case "":
		if key != "mode" {
			return fmt.Errorf("unsupported top-level field %q", key)
		}
		p.Mode = cloak.Mode(value)
	case "ipv4":
		n, err := parseInt(key, value)
		if err != nil {
			return err
		}
		switch key {
		case "preserve_bits":
			p.IPv4.PreserveBits = n
		case "truncate_prefix":
			p.IPv4.TruncatePrefix = n
		default:
			return fmt.Errorf("unsupported ipv4 field %q", key)
		}
	case "ipv6":
		n, err := parseInt(key, value)
		if err != nil {
			return err
		}
		switch key {
		case "preserve_bits":
			p.IPv6.PreserveBits = n
		case "truncate_prefix":
			p.IPv6.TruncatePrefix = n
		default:
			return fmt.Errorf("unsupported ipv6 field %q", key)
		}
	case "verification":
		if key != "fail_on_raw_leak" {
			return fmt.Errorf("unsupported verification field %q", key)
		}
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%s must be boolean", key)
		}
		p.Verification.FailOnRawLeak = b
	default:
		return fmt.Errorf("unsupported section %q", section)
	}
	return nil
}

func parseInt(key, value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be integer", key)
	}
	return n, nil
}

func stripComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		return line[:idx]
	}
	return line
}

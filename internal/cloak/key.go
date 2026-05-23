package cloak

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"prefixcloak/internal/pan"
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, pan.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func LoadKey(hexValue, base64Value, file string) ([]byte, error) {
	sources := 0
	for _, v := range []string{hexValue, base64Value, file} {
		if v != "" {
			sources++
		}
	}
	if sources != 1 {
		return nil, errors.New("provide exactly one key source: --key-hex, --key-base64, or --key-file")
	}

	var (
		key []byte
		err error
	)
	switch {
	case hexValue != "":
		key, err = hex.DecodeString(strings.TrimSpace(hexValue))
	case base64Value != "":
		key, err = base64.StdEncoding.DecodeString(strings.TrimSpace(base64Value))
	case file != "":
		var data []byte
		data, err = os.ReadFile(file)
		if err == nil {
			key, err = decodeKeyText(string(data))
		}
	}
	if err != nil {
		return nil, err
	}
	if len(key) != pan.KeySize {
		return nil, fmt.Errorf("invalid PrefixCloak key size: got %d bytes, want %d", len(key), pan.KeySize)
	}
	return key, nil
}

func decodeKeyText(s string) ([]byte, error) {
	value := strings.TrimSpace(s)
	if strings.HasPrefix(value, "hex:") {
		return hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(value, "hex:")))
	}
	if strings.HasPrefix(value, "base64:") {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(value, "base64:")))
	}
	if key, err := hex.DecodeString(value); err == nil {
		return key, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

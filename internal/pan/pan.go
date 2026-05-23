package pan

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"net"
)

const KeySize = 32

type Transformer struct {
	block cipher.Block
	pad   [aes.BlockSize]byte
}

func New(key []byte) (*Transformer, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}
	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		return nil, err
	}
	t := &Transformer{block: block}
	copy(t.pad[:], key[aes.BlockSize:])
	return t, nil
}

func (t *Transformer) Transform(ip net.IP) (net.IP, error) {
	if ip == nil {
		return nil, errors.New("nil IP")
	}
	if v4 := ip.To4(); v4 != nil {
		out := transformBits(t.block, t.pad, v4, 32)
		return net.IP(out), nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, errors.New("invalid IP")
	}
	out := transformBits(t.block, t.pad, v6, 128)
	return net.IP(out), nil
}

func transformBits(block cipher.Block, pad [aes.BlockSize]byte, src []byte, bits int) []byte {
	out := append([]byte(nil), src...)
	for bit := 0; bit < bits; bit++ {
		input := pad
		copyPrefixBits(input[:], src, bit)

		var encrypted [aes.BlockSize]byte
		block.Encrypt(encrypted[:], input[:])
		if encrypted[0]&0x80 != 0 {
			flipBit(out, bit)
		}
	}
	return out
}

func copyPrefixBits(dst, src []byte, bits int) {
	fullBytes := bits / 8
	copy(dst, src[:fullBytes])
	if rem := bits % 8; rem != 0 {
		mask := byte(0xff << (8 - rem))
		dst[fullBytes] = (dst[fullBytes] &^ mask) | (src[fullBytes] & mask)
	}
}

func flipBit(buf []byte, bit int) {
	buf[bit/8] ^= byte(0x80 >> (bit % 8))
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "invalid PrefixCloak key size"
}

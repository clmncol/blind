package blind

import (
	"bytes"
	"errors"
	"fmt"
)

func Xor(a, b []byte) ([]byte, error) {
	// Error handling
	if len(a) != len(b) {
		fmt.Printf("A had length of %v, and B had length of %v", len(a), len(b))
		return nil, errors.New("input byte slices must be the same length")
	}

	// Create output byte slice
	o := make([]byte, len(a))

	// For each bit, bitwise XOR
	for i := 0; i < len(a); i++ {
		o[i] = a[i] ^ b[i]
	}
	return o, nil
}

func SizeKeyForXor(k []byte, l int) []byte {
	var o []byte
	// If the pt is smaller or equally sized to the key, just use the overlap,
	// otherwise: repeat as needed and cut to size.
	if l <= len(k) {
		o = k[:l]
	} else {
		km := l / len(k)
		o = bytes.Repeat(k[:], km+1)[:l]
	}
	return o
}

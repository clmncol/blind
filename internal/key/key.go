package key

import (
	"encoding/base64"
	"fmt"
)

type Key struct {
	data []byte
	size int
}

// NewKey initializes a key of the given size.
func NewKey(size int) *Key {
	return &Key{
		data: make([]byte, size),
		size: size,
	}
}

func (k *Key) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k.data)), nil
}

func (k *Key) UnmarshalText(text []byte) error {
	decoded, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(decoded) != k.size {
		return fmt.Errorf("invalid key length: expected %d, got %d", k.size, len(decoded))
	}
	copy(k.data, decoded)
	return nil
}

// Bytes returns the underlying byte slice.
func (k *Key) Bytes() []byte {
	return k.data
}

// SetBytes sets the key data, ensuring the size matches.
func (k *Key) SetBytes(data []byte) error {
	if len(data) != k.size {
		return fmt.Errorf("invalid key length: expected %d, got %d", k.size, len(data))
	}
	copy(k.data, data)
	return nil
}

func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(k.data)
}

package blind

import (
	"crypto/sha256"
	"io"

	support "github.com/Grant-Eckstein/blind/support"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

func KDF(key []byte) ([]byte, []byte, error) {
	// Create nonce
	salt, err := support.Bytes(32)
	if err != nil {
		return nil, nil, err
	}

	// Hash key before use in KDF
	key = argon2.Key(key, salt, 3, 32*1024, 4, 256)

	// Configure new reader
	hkdf := hkdf.New(sha256.New, key, nil, nil)

	// Read new key
	newKey := make([]byte, 256)
	if _, err := io.ReadFull(hkdf, newKey); err != nil {
		return nil, nil, err
	}

	return newKey, salt, nil
}

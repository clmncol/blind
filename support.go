package blind

import (
	"crypto/aes"
	"crypto/rand"
	"strings"
)

func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	err := randBytes(b)
	if err != nil {
		return nil, err
	} else {
		return b, nil
	}
}

func randBytes(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// PKCS7 padding
func PKCS7Pad(d []byte) []byte {
	// aes.BlockSize = 16 FYI
	m := aes.BlockSize - len(d)%aes.BlockSize

	// Pad with repeating pad count
	pS := []byte(strings.Repeat(string(int32(m)), m))

	o := append(d, pS...)

	return o
}

func PKCS7Unpad(d []byte) []byte {
	m := int(d[len(d)-1])
	return d[0 : len(d)-m]
}

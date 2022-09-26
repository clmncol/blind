package blind

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
)

type AESConfig struct {
	Key []byte
	Iv  []byte
}

func NewAESConfig() AESConfig {
	key, err := Bytes(32)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	iv, err := Bytes(aes.BlockSize)
	if err != nil {
		log.Fatalf("Error generating iv: %v", err)
	}

	return AESConfig{
		Key: key,
		Iv:  iv,
	}
}

func (a *AESConfig) Encrypt(pt []byte) []byte {
	// Pad all input
	pt = PKCS7Pad(pt)

	b, err := aes.NewCipher(a.Key)
	if err != nil {
		log.Fatalf("Error generating CB: %v", err)
	}

	ct := make([]byte, len(pt))
	m := cipher.NewCBCEncrypter(b, a.Iv)
	m.CryptBlocks(ct, pt)
	return ct
}

func (a *AESConfig) Decrypt(ct []byte) []byte {
	b, err := aes.NewCipher(a.Key)
	if err != nil {
		log.Fatalf("Error generating CB: %v", err)
	}

	pt := make([]byte, len(ct))
	m := cipher.NewCBCDecrypter(b, a.Iv)
	m.CryptBlocks(pt, ct)

	return PKCS7Unpad(pt)
}

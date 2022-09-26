package blind

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
)

func (a *Blind) Encrypt(pt []byte) []byte {
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

func (a *Blind) Decrypt(ct []byte) []byte {
	b, err := aes.NewCipher(a.Key)
	if err != nil {
		log.Fatalf("Error generating CB: %v", err)
	}

	pt := make([]byte, len(ct))
	m := cipher.NewCBCDecrypter(b, a.Iv)
	m.CryptBlocks(pt, ct)

	return PKCS7Unpad(pt)
}

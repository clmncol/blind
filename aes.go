package blind

import (
	"crypto/aes"
	"crypto/cipher"
)

type AESConfig struct {
	Key []byte
	Iv  []byte
}

func NewAESConfig() (AESConfig, error) {
	key, err := Bytes(32)
	if err != nil {
		return AESConfig{}, err
	}

	iv, err := Bytes(aes.BlockSize)
	if err != nil {
		return AESConfig{}, err
	}

	return AESConfig{
		Key: key,
		Iv:  iv,
	}, nil
}

func (a *AESConfig) Encrypt(pt []byte) ([]byte, error) {
	// Pad all input
	pt = PKCS7Pad(pt)

	b, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(pt))
	m := cipher.NewCBCEncrypter(b, a.Iv)
	m.CryptBlocks(ct, pt)
	return ct, nil
}

func (a *AESConfig) Decrypt(ct []byte) ([]byte, error) {
	b, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}

	pt := make([]byte, len(ct))
	m := cipher.NewCBCDecrypter(b, a.Iv)
	m.CryptBlocks(pt, ct)

	return PKCS7Unpad(pt), nil
}

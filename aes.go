package blind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

type AESConfig struct {
	CBC AESCBCConfig
}

type AESCBCConfig struct {
	Key []byte
	Iv  []byte
}

func NewAESConfig() (AESConfig, error) {
	cbc, err := NewAESCBCConfig()
	if err != nil {
		return AESConfig{}, err
	}
	return AESConfig{
		CBC: cbc,
	}, nil
}

func NewAESCBCConfig() (AESCBCConfig, error) {
	key, err := Bytes(32)
	if err != nil {
		return AESCBCConfig{}, err
	}

	iv, err := Bytes(aes.BlockSize)
	if err != nil {
		return AESCBCConfig{}, err
	}

	return AESCBCConfig{
		Key: key,
		Iv:  iv,
	}, nil
}

func (a *AESCBCConfig) Encrypt(pt []byte) ([]byte, error) {
	// Pad all input
	pt = PKCS7Pad(pt)

	/*** Lengthen the key to the size of pt for key whitening ***/
	// Hash key for security
	sc := sha256.Sum256(a.Key)
	k := SizeKeyForXor(sc[:], len(pt))

	// XOR pt with new key (key whitening pt 1)
	pt, err := Xor(pt, k)
	if err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(pt))
	m := cipher.NewCBCEncrypter(b, a.Iv)
	m.CryptBlocks(ct, pt)

	// XOR ct with new key (key whitening pt 2)
	ct, err = Xor(ct, k)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (a *AESCBCConfig) Decrypt(ct []byte) ([]byte, error) {

	/*** Lengthen the key to the size of pt for key whitening ***/
	// Hash key for security
	sc := sha256.Sum256(a.Key)
	k := SizeKeyForXor(sc[:], len(ct))

	// XOR pt with new key (key whitening pt 1)
	ct, err := Xor(ct, k)
	if err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}

	pt := make([]byte, len(ct))
	m := cipher.NewCBCDecrypter(b, a.Iv)
	m.CryptBlocks(pt, ct)

	// XOR pt with new key (key whitening pt 1)
	pt, err = Xor(pt, k)
	if err != nil {
		return nil, err
	}

	return PKCS7Unpad(pt), nil
}

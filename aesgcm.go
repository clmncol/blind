package blind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

type AESGCMConfig struct {
	Key   []byte
	Iv    []byte
	Nonce []byte
}

func NewAESGCMConfig() (AESGCMConfig, error) {
	key, err := Bytes(32)
	if err != nil {
		return AESGCMConfig{}, err
	}

	iv, err := Bytes(aes.BlockSize)
	if err != nil {
		return AESGCMConfig{}, err
	}

	n, err := Bytes(12)
	if err != nil {
		return AESGCMConfig{}, err
	}

	return AESGCMConfig{
		Key:   key,
		Iv:    iv,
		Nonce: n,
	}, nil
}

func (a *AESGCMConfig) Encrypt(pt, ad []byte) ([]byte, error) {
	// Pad
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

	m, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	ct := m.Seal(nil, a.Nonce, pt, ad)

	// XOR ct with new key (key whitening pt 2)
	sc = sha256.Sum256(a.Key)
	k = SizeKeyForXor(sc[:], len(ct))

	ct, err = Xor(ct, k)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (a *AESGCMConfig) Decrypt(ct, ad []byte) ([]byte, error) {
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

	m, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	pt, err := m.Open(nil, a.Nonce, ct, ad)
	if err != nil {
		return nil, err
	}

	// XOR ct with new key (key whitening pt 2)
	// Hash key for security
	sc = sha256.Sum256(a.Key)
	k = SizeKeyForXor(sc[:], len(pt))

	// XOR pt with new key (key whitening pt 1)
	pt, err = Xor(pt, k)
	if err != nil {
		return nil, err
	}

	return PKCS7Unpad(pt), nil
}

package blind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"

	config "github.com/Grant-Eckstein/blind/block/aes"
	support "github.com/Grant-Eckstein/blind/support"
	xor "github.com/Grant-Eckstein/blind/xor"
)

type AESGCMConfig struct {
	Key   []byte
	Iv    []byte
	Nonce []byte
}

func (c *AESGCMConfig) Encrypt(plaintext []byte) ([]byte, error) {
	// Pad
	plaintext = support.PKCS7Pad(plaintext)

	/*** Lengthen the key to the size of plaintext for key whitening ***/
	// Hash key for security
	sc := sha256.Sum256(c.Key)
	k := xor.SizeKeyForXor(sc[:], len(plaintext))

	// XOR plaintext with new key (key whitening plaintext 1)
	plaintext, err := xor.Xor(plaintext, k)
	if err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	m, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	ct := m.Seal(nil, c.Nonce, plaintext, nil)

	// XOR ct with new key (key whitening plaintext 2)
	sc = sha256.Sum256(c.Key)
	k = xor.SizeKeyForXor(sc[:], len(ct))

	ct, err = xor.Xor(ct, k)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (c *AESGCMConfig) Decrypt(ciphertext []byte) ([]byte, error) {
	/*** Lengthen the key to the size of pt for key whitening ***/
	// Hash key for security
	sc := sha256.Sum256(c.Key)
	k := xor.SizeKeyForXor(sc[:], len(ciphertext))

	// XOR pt with new key (key whitening pt 1)
	ct, err := xor.Xor(ciphertext, k)
	if err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	m, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	pt, err := m.Open(nil, c.Nonce, ct, nil)
	if err != nil {
		return nil, err
	}

	// XOR ct with new key (key whitening pt 2)
	// Hash key for security
	sc = sha256.Sum256(c.Key)
	k = xor.SizeKeyForXor(sc[:], len(pt))

	// XOR pt with new key (key whitening pt 1)
	pt, err = xor.Xor(pt, k)
	if err != nil {
		return nil, err
	}

	return support.PKCS7Unpad(pt), nil
}

func (c *AESGCMConfig) Marshall() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"key":   c.Key,
		"iv":    c.Iv,
		"nonce": c.Nonce,
	})
}

func (c *AESGCMConfig) Unmarshall(data []byte) error {
	var fields struct {
		Key   []byte `json:"key"`
		Iv    []byte `json:"iv"`
		Nonce []byte `json:"nonce"`
	}
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	c.Key = fields.Key
	c.Iv = fields.Iv
	return nil
}

func NewAESGCMConfig() config.AESConfig {
	// Generate values
	key, _ := support.Bytes(32)
	iv, _ := support.Bytes(aes.BlockSize)
	n, _ := support.Bytes(12)

	return &AESGCMConfig{
		Key:   key,
		Iv:    iv,
		Nonce: n,
	}
}

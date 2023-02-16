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

type AESCBCConfig struct {
	Key []byte
	Iv  []byte
}

func (c *AESCBCConfig) Encrypt(plaintext []byte) ([]byte, error) {
	// Pad all input
	plaintext = support.PKCS7Pad(plaintext)

	/*** Lengthen the key to the size of plaintext for key whitening ***/
	// Hash key for security
	sc := sha256.Sum256(c.Key)
	k := xor.SizeKeyForXor(sc[:], len(plaintext))

	// XOR plaintext with new key (key whitening plaintext 1)
	pt, err := xor.Xor(plaintext, k)
	if err != nil {
		return nil, err
	}

	b, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	m := cipher.NewCBCEncrypter(b, c.Iv)
	m.CryptBlocks(ciphertext, pt)

	// XOR ct with new key (key whitening plaintext 2)
	ciphertext, err = xor.Xor(ciphertext, k)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func (c *AESCBCConfig) Decrypt(ciphertext []byte) ([]byte, error) {
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

	plaintext := make([]byte, len(ct))
	m := cipher.NewCBCDecrypter(b, c.Iv)
	m.CryptBlocks(plaintext, ct)

	// XOR pt with new key (key whitening pt 1)
	plaintext, err = xor.Xor(plaintext, k)
	if err != nil {
		return nil, err
	}

	return support.PKCS7Unpad(plaintext), nil
}

func (c *AESCBCConfig) Marshall() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"key": c.Key,
		"iv":  c.Iv,
	})
}

func (c *AESCBCConfig) Unmarshall(data []byte) error {
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

func NewAESCBCConfig() config.AESConfig {
	// Generate values
	key, _ := support.Bytes(32)
	iv, _ := support.Bytes(aes.BlockSize)

	return &AESCBCConfig{
		Key: key,
		Iv:  iv,
	}
}

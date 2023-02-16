package blind

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	config "github.com/Grant-Eckstein/blind/block/rsa"
	"golang.org/x/crypto/blake2b"
)

type RSAConfig struct {
	Keys *rsa.PrivateKey
}

func (c *RSAConfig) Encrypt(plaintext []byte) ([]byte, error) {
	hash, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, &c.Keys.PublicKey, plaintext, nil)
	return ciphertext, err
}

func (c *RSAConfig) Decrypt(ciphertext []byte) ([]byte, error) {
	hash, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, c.Keys, ciphertext, nil)
	return plaintext, err
}

func (c *RSAConfig) Marshall() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"keys": c.Keys,
	})
}

func (c *RSAConfig) Unmarshall(data []byte) error {
	var fields struct {
		Keys *rsa.PrivateKey `json:"keys"`
	}
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	c.Keys = fields.Keys
	return nil
}

func NewRSAOAEPConfig() config.RSAConfig {
	rng := rand.Reader
	k, _ := rsa.GenerateKey(rng, 4096)

	return &RSAConfig{
		Keys: k,
	}
}

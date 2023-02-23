package blind

import (
	"crypto/ed25519"
	"encoding/json"

	"golang.org/x/crypto/sha3"
)

type ED25519Signature struct {
	Message   []byte
	Signature []byte
}

func (c *ED25519Signature) Marshall() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"message":   c.Message,
		"signature": c.Signature,
	})
}

func (c *ED25519Signature) Unmarshall(data []byte) error {
	var fields struct {
		Message   []byte `json:"message"`
		Signature []byte `json:"signature"`
	}
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	c.Message = fields.Message
	c.Signature = fields.Signature
	return nil
}

func newED25519Signature(message []byte, privateKey *ed25519.PrivateKey) *ED25519Signature {
	hash := sha3.Sum256(message)
	signature := ed25519.Sign(*privateKey, hash[:])

	return &ED25519Signature{
		Message:   hash[:],
		Signature: signature,
	}
}

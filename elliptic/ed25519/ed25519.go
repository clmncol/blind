package blind

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
)

type ED25519Config struct {
	PublicKey  *ed25519.PublicKey
	PrivateKey *ed25519.PrivateKey
}

func (c *ED25519Config) Sign(data []byte) ([]byte, error) {
	signature := newED25519Signature(data, c.PrivateKey)
	o, err := signature.Marshall()
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (c *ED25519Config) Verify(foreignPublicKey *ED25519Config, signatureJson []byte) (bool, error) {
	signature := ED25519Signature{}
	err := signature.Unmarshall(signatureJson)
	if err != nil {
		return false, errors.New("unable to unmarshal signature json")
	}

	return ed25519.Verify(*foreignPublicKey.PublicKey, signature.Message, signature.Signature), nil
}

func (c *ED25519Config) Marshall() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"publickey":  c.PublicKey,
		"privatekey": c.PrivateKey,
	})
}

func (c *ED25519Config) Unmarshall(data []byte) error {
	var fields struct {
		PublicKey  *ed25519.PrivateKey `json:"publickey"`
		PrivateKey *ed25519.PrivateKey `json:"privatekey"`
	}
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	c.PublicKey = (*ed25519.PublicKey)(fields.PublicKey)
	c.PrivateKey = fields.PrivateKey
	return nil
}

func NewED25519Config() *ED25519Config {
	publicKey, PrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	return &ED25519Config{
		PublicKey:  &publicKey,
		PrivateKey: &PrivateKey,
	}
}

package blind

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type ECDSASignature struct {
	R        *big.Int
	S        *big.Int
	DataHash []byte
}

func (c *ECDSASignature) Marshall() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"r":        c.R,
		"s":        c.S,
		"datahash": c.DataHash,
	})
}

func (c *ECDSASignature) Unmarshall(data []byte) error {
	var fields struct {
		R        *big.Int `json:"r"`
		S        *big.Int `json:"s"`
		DataHash []byte   `json:"datahash"`
	}
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	c.R = fields.R
	c.S = fields.S
	c.DataHash = fields.DataHash
	return nil
}

func newECDSASignature(data []byte, privateKey *ecdsa.PrivateKey) (*ECDSASignature, error) {
	h := sha3.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h[:])
	if err != nil {
		return &ECDSASignature{}, err
	}

	return &ECDSASignature{
		R:        r,
		S:        s,
		DataHash: h[:],
	}, nil
}

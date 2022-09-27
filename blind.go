package blind

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"log"

	"golang.org/x/crypto/blake2s"
)

type Blind struct {
	AES AESConfig
	RSA RSAConfig
}

// TODO - implement generate RSAConfig only if used
func New() (Blind, error) {
	a, err := NewAESConfig()
	if err != nil {
		return Blind{}, err
	}

	r, err := NewRSAConfig()
	if err != nil {
		return Blind{}, err
	}

	return Blind{
		AES: a,
		RSA: r,
	}, nil
}

// Export Blind configuration to JSON
func (b *Blind) Export() []byte {
	o, err := json.Marshal(b)
	if err != nil {
		log.Fatal(err)
	}

	return o
}

// Import Blind configuration from JSON
func Import(j []byte) Blind {
	// Create basic template
	var b Blind
	h, err := blake2s.New256(nil)
	if err != nil {
		log.Fatal(err)
	}

	b.AES = AESConfig{}
	b.RSA = RSAConfig{
		Hash: h,
		Rng:  rand.Reader,
		Sig:  crypto.BLAKE2b_256,
	}

	err = json.Unmarshal(j, &b)

	if err != nil {
		log.Fatal(err)
	}

	return b
}

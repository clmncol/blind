package blind

import (
	"encoding/json"
	"log"
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
	var b Blind
	err := json.Unmarshal(j, &b)

	if err != nil {
		log.Fatal(err)
	}

	return b
}

package blind

import (
	"crypto/aes"
	"encoding/json"
	"log"
)

type Blind struct {
	Key []byte
	Iv  []byte
}

func New() Blind {
	key, err := Bytes(32)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	iv, err := Bytes(aes.BlockSize)
	if err != nil {
		log.Fatalf("Error generating iv: %v", err)
	}

	return Blind{
		Key: key,
		Iv:  iv,
	}
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

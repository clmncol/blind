package blind

import (
	"crypto/aes"
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

package chacha

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	i "github.com/Grant-Eckstein/blind/internal/interfaces"
	c "golang.org/x/crypto/chacha20poly1305"
)

type ChachaSession struct {
	Key []byte
}

func New() (i.StreamSessionProvider, error) {
	// New key
	key := make([]byte, c.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// Error if there is a problem loading the cipher
	if _, err := c.NewX(key); err != nil {
		return nil, err
	} else {

		// Store only the key
		return &ChachaSession{
			Key: key,
		}, nil
	}
}

func (cc *ChachaSession) Encrypt(plaintext, ad []byte) ([]byte, error) {
	cipher, err := c.NewX(cc.Key)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	n, err := nonce()
	if err != nil {
		return nil, err
	}

	ct := cipher.Seal(n, n, plaintext, ad)
	return ct, nil
}

func (cc *ChachaSession) Decrypt(msg, ad []byte) ([]byte, error) {
	if len(msg) <= c.NonceSizeX {
		return nil, errors.New("ct too short")
	}

	// Separate nonce from ciphertext
	n, ct := msg[:c.NonceSizeX], msg[c.NonceSizeX:]

	// Setup cipher
	cipher, err := c.NewX(cc.Key)
	if err != nil {
		return nil, err
	}

	// Decrypt
	return cipher.Open(nil, n, ct, ad)
}

func (cc *ChachaSession) Export() ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(cc.Key)))
	base64.StdEncoding.Encode(dst, cc.Key)
	return dst, nil
}

func (cc *ChachaSession) Import(k []byte) error {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(k)))
	_, err := base64.StdEncoding.Decode(dst, k)
	if err != nil {
		return err
	}
	cc.Key = dst[:]
	return nil
}

func nonce() ([]byte, error) {
	nonce := make([]byte, c.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

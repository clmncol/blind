package identity

import "github.com/Grant-Eckstein/blind/internal/key"

type privateKey struct {
	key.Key
}

// NewPrivateKey creates a new privateKey.
func NewPrivateKey() *privateKey {
	return &privateKey{*key.NewKey(4000)}
}

type publicKey struct {
	key.Key
}

// NewPublicKey creates a new publicKey.
func NewPublicKey() *publicKey {
	return &publicKey{*key.NewKey(1952)}
}

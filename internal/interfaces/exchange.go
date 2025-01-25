package interfaces

import "errors"

type ExchangeProvider interface {
	Provider
	// Public exports the public key for use in the exchange
	Public() []byte
}

type KemExchangeProvider interface {
	ExchangeProvider

	// Send uses the recipient's public key and crypto/rand to
	// generate a shared secret and ciphertext to communicate
	// it back to the recipient
	Send([]byte) ([]byte, []byte)

	// Receive uses the received cipher text and our private key to
	// generate the shared secret
	Receive([]byte) []byte
}

type DHExchangeProvider interface {
	ExchangeProvider

	Shared([]byte) ([]byte, error)
}

const (
	X448ExchangeType     = 1
	KyberKemExchangeType = 2
)

var (
	ErrWrongExchangeType = errors.New("wrong exchange type")
)

package kem

import (
	"bytes"
	"crypto/rand"

	"github.com/BurntSushi/toml"
	i "github.com/Grant-Eckstein/blind/internal/interfaces"
	kyber "github.com/cloudflare/circl/kem/kyber/kyber512"
)

// KyberExchangeExport is used for writing KyberExchange to disk
type KyberExchangeExport struct {
	Type       int
	PrivateKey [kyber.PrivateKeySize]byte
	PublicKey  [kyber.PublicKeySize]byte
}

// newExportObj is used for writing the KyberExchange object to disk
func newExportObj(pri, pub []byte) *KyberExchangeExport {
	return &KyberExchangeExport{
		Type:       i.KyberKemExchangeType,
		PrivateKey: [kyber.PrivateKeySize]byte(pri),
		PublicKey:  [kyber.PublicKeySize]byte(pub),
	}
}

// KyberExchange is a Kyber512 KEM
type KyberExchange struct {
	Type       int
	PrivateKey *kyber.PrivateKey
	PublicKey  *kyber.PublicKey
}

// Export writes the entire object to a byte slice for writing to disk
func (k *KyberExchange) Export() ([]byte, error) {
	pri := make([]byte, kyber.PrivateKeySize)
	k.PrivateKey.Pack(pri)

	pub := make([]byte, kyber.PublicKeySize)
	k.PublicKey.Pack(pub)

	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(newExportObj(pri, pub)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Import imports the entire object from disk
func (k *KyberExchange) Import(export []byte) error {
	_, err := toml.Decode(string(export), &k)
	return err
}

// Send generates the shared secret and the cipher text (using the recipient's
// `k.Public()`) to send it to the recipient
func (k *KyberExchange) Send(recipientPackedPublicKey []byte) ([]byte, []byte) {
	pub := new(kyber.PublicKey)
	pub.Unpack(recipientPackedPublicKey)

	ct := make([]byte, kyber.CiphertextSize)
	ss := make([]byte, kyber.SharedKeySize)
	pub.EncapsulateTo(ct, ss, nil)
	return ct, ss
}

// Receive processes the ciphertext received from the sender
// (using this instance's k.Public key) into a shared secret.
func (k *KyberExchange) Receive(ct []byte) []byte {
	ss := make([]byte, kyber.SharedKeySize)
	k.PrivateKey.DecapsulateTo(ss, ct)
	return ss
}

// Public packs the public key into a byte slice for use with the recipient's k.Send
func (k *KyberExchange) Public() []byte {
	p := make([]byte, kyber.PublicKeySize)
	k.PublicKey.Pack(p)
	return p
}

func New() (i.KemExchangeProvider, error) {
	if pub, pri, err := kyber.GenerateKeyPair(rand.Reader); err != nil {
		return nil, err
	} else {
		return &KyberExchange{
			Type:       i.KyberKemExchangeType,
			PublicKey:  pub,
			PrivateKey: pri,
		}, nil
	}
}

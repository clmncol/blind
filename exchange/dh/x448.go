package dh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
	i "github.com/Grant-Eckstein/blind/internal/interfaces"
	"github.com/cloudflare/circl/dh/x448"
)

type X448Exchange struct {
	Type       int
	PrivateKey x448Key
	PublicKey  x448Key
}

func New() (i.DHExchangeProvider, error) {
	ex := new(X448Exchange)
	ex.Type = i.X448ExchangeType

	pri := new(x448.Key)
	if _, err := io.ReadFull(rand.Reader, pri[:]); err != nil {
		return nil, fmt.Errorf("unable to generate private key: %s", err.Error())
	}

	pub := new(x448.Key)
	x448.KeyGen(pub, pri)

	ex.PrivateKey = *NewX448Key()
	ex.PublicKey = *NewX448Key()

	if err := ex.PrivateKey.SetBytes(pri[:]); err != nil {
		return nil, err
	}
	if err := ex.PublicKey.SetBytes(pub[:]); err != nil {
		return nil, err
	}

	return ex, nil
}

func (x *X448Exchange) Public() []byte {
	return x.PublicKey.Bytes()
}

func (x *X448Exchange) Shared(foreignPublic []byte) ([]byte, error) {
	shared := new(x448.Key)

	if !x448.Shared(shared, (*x448.Key)(x.PrivateKey.Bytes()), (*x448.Key)(foreignPublic)) {
		return nil, fmt.Errorf("issue creating shared key")
	}
	return shared[:], nil
}

func (x *X448Exchange) Export() ([]byte, error) {
	// Export
	var buf = new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(x); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (x *X448Exchange) Import(export []byte) error {
	_, err := toml.Decode(string(export), &x)
	return err
}

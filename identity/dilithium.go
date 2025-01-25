package identity

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/BurntSushi/toml"
	i "github.com/Grant-Eckstein/blind/internal/interfaces"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

type DilithiumIdentityExport struct {
	Type       int
	PublicKey  *publicKey
	PrivateKey *privateKey
}

func NewExport() DilithiumIdentityExport {
	return DilithiumIdentityExport{
		Type:       i.DilithiumIdentityType,
		PublicKey:  NewPublicKey(),
		PrivateKey: NewPrivateKey(),
	}
}

type DilithiumIdentity struct {
	Type       int
	PublicKey  mode3.PublicKey
	PrivateKey mode3.PrivateKey
}

func New() (i.IdentityProvider, error) {
	pub, pri, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &DilithiumIdentity{
		Type:       i.DilithiumIdentityType,
		PublicKey:  *pub,
		PrivateKey: *pri,
	}, nil
}

func (di *DilithiumIdentity) Sign(data []byte) ([]byte, error) {
	var signature [mode3.SignatureSize]byte
	mode3.SignTo(&di.PrivateKey, data, signature[:])
	return signature[:], nil
}

func (di *DilithiumIdentity) Verify(data []byte, signature []byte) (bool, error) {
	return mode3.Verify(&di.PublicKey, data, signature), nil
}

// Identity providers must be exportable to a byte slice
func (di *DilithiumIdentity) Export() ([]byte, error) {
	export := NewExport()

	pubBuf := new([1952]byte)
	di.PublicKey.Pack(pubBuf)
	err := export.PublicKey.SetBytes(pubBuf[:])
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	priBuf := new([4000]byte)
	di.PrivateKey.Pack(priBuf)
	// export.PrivateKey = (*privateKey)(priBuf)
	export.PrivateKey.SetBytes(priBuf[:])

	// Export
	var buf = new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(export); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (di *DilithiumIdentity) Import(data []byte) error {
	export := NewExport()
	if _, err := toml.Decode(string(data), &export); err != nil {
		return err
	}
	if export.Type != i.DilithiumIdentityType {
		return i.ErrWrongIdentityType
	}

	// Import
	pubBuf := new([1952]byte)
	di.PublicKey.Unpack(pubBuf)
	export.PublicKey.SetBytes(pubBuf[:])
	// export.PublicKey = (*publicKey)(pubBuf)

	priBuf := new([4000]byte)
	di.PrivateKey.Pack(priBuf)
	export.PrivateKey.SetBytes(priBuf[:])
	// export.PrivateKey = (*privateKey)(priBuf)

	di.Type = export.Type
	return nil
}

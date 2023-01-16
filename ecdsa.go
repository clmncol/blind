package blind

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

func NewEcDSA(reader io.Reader) (*ecdsa.PrivateKey, error) {
	pri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return pri, nil
}

func ECDH(l *ecdsa.PrivateKey, d []byte) []byte {
	sharedX, sharedY := l.Curve.ScalarMult(l.X, l.Y, d)

	h := sha256.Sum256(append(sharedX.Bytes(), sharedY.Bytes()...))
	return h[:]
}

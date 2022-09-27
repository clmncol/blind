package blind

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"hash"
	"io"
	"log"

	"golang.org/x/crypto/blake2b"
)

type RSAConfig struct {
	Keys *rsa.PrivateKey
	Hash hash.Hash `json:"hash"`
	Sig  crypto.Hash
	Rng  io.Reader
}

func NewRSAConfig() (RSAConfig, error) {
	return RSAConfig{}, nil
}

func (r *RSAConfig) GenerateKeys() error {
	rg := rand.Reader

	k, err := rsa.GenerateKey(rg, 4096)
	if err != nil {
		log.Fatalln(err)
		return err
	}

	h, err := blake2b.New256(nil)
	if err != nil {
		log.Fatalln(err)
		return err
	}

	// Set values
	r.Keys = k
	r.Hash = h
	r.Sig = crypto.BLAKE2b_256
	r.Rng = rg
	return nil
}

func (r *RSAConfig) Encrypt(pt, l []byte) ([]byte, error) {
	if r.Keys == nil {
		return nil, errors.New("RSA key not set")
	}

	ct, err := rsa.EncryptOAEP(r.Hash, r.Rng, &r.Keys.PublicKey, pt, l)
	if err != nil {
		return nil, err
	}

	return ct, nil

}

func (r *RSAConfig) Decrypt(ct, l []byte) ([]byte, error) {
	if r.Keys == nil {
		return nil, errors.New("RSA key not set")
	}

	pt, err := rsa.DecryptOAEP(r.Hash, r.Rng, r.Keys, ct, l)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	return pt, nil
}

func (r *RSAConfig) Sign(pt []byte) ([]byte, error) {
	if r.Keys == nil {
		return nil, errors.New("RSA key not set")
	}

	h := r.Hash.Sum(pt)

	s, err := rsa.SignPKCS1v15(r.Rng, r.Keys, r.Sig, h)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	return s, nil
}

func (r *RSAConfig) Verify(pt, s []byte) (bool, error) {
	if r.Keys == nil {
		return false, errors.New("RSA key not set")
	}

	ns, err := r.Sign(pt)
	if err != nil {
		return false, err
	}
	if bytes.Equal(s, ns) {
		return true, nil
	}
	return false, nil
}

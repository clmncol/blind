package blind

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
	r := rand.Reader

	k, err := rsa.GenerateKey(r, 4096)
	if err != nil {
		log.Fatalln(err)
		return RSAConfig{}, err
	}

	h, err := blake2b.New256(nil)
	if err != nil {
		log.Fatalln(err)
		return RSAConfig{}, err
	}

	return RSAConfig{
		Keys: k,
		Hash: h,
		Sig:  crypto.BLAKE2b_256,
		Rng:  r,
	}, nil
}

func (r *RSAConfig) Encrypt(pt, l []byte) ([]byte, error) {

	ct, err := rsa.EncryptOAEP(r.Hash, r.Rng, &r.Keys.PublicKey, pt, l)
	if err != nil {
		return nil, err
	}

	return ct, nil

}

func (r *RSAConfig) Decrypt(ct, l []byte) ([]byte, error) {
	pt, err := rsa.DecryptOAEP(r.Hash, r.Rng, r.Keys, ct, l)
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}
	return pt, nil
}

func (r *RSAConfig) Sign(pt []byte) (error, []byte) {
	h := r.Hash.Sum(pt)

	s, err := rsa.SignPKCS1v15(r.Rng, r.Keys, r.Sig, h)
	if err != nil {
		log.Fatalln(err)
		return err, nil
	}
	return nil, s
}

func (r *RSAConfig) Verify(pt, s []byte) (error, bool) {
	err, ns := r.Sign(pt)
	if err != nil {
		return err, false
	}
	if bytes.Equal(s, ns) {
		return nil, true
	}
	return nil, false
}

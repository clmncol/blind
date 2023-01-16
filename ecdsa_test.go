package blind

import (
	"bytes"
	"crypto/rand"
	"log"
	"testing"
)

func TestEcdsaDH(t *testing.T) {
	k1, err := NewEcDSA(rand.Reader)
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	k2, err := NewEcDSA(rand.Reader)
	if err != nil {
		log.Println(err)
		t.Fail()
	}

	s1 := ECDH(k1, k2.D.Bytes())
	s2 := ECDH(k2, k1.D.Bytes())

	if !bytes.Equal(s1, s2) {
		log.Println("Shared secret is not equal!")
		log.Printf("Shared Secret 1 is '%v'\n", s1)
		log.Printf("Shared Secret 2 is '%v'\n", s2)
		t.Fail()
	}

}

package blind

import (
	"bytes"
	"testing"
)

func TestBlind_RSAEncryptDecrypt(t *testing.T) {
	d := []byte("hello, world")
	l := []byte("test label")

	b, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Generate new RSA Key
	err = b.RSA.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := b.RSA.Encrypt(d, l)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := b.RSA.Decrypt(ct, l)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(pt, d) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(d), string(pt))
	}

}

func TestBlind_RSASignVerify(t *testing.T) {
	d := []byte("Hello, world")

	b, err := New()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Created new object")

	s, err := b.RSA.Sign(d)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Signed plaintext")

	v, err := b.RSA.Verify(d, s)
	if err != nil {
		t.Fatal(err)
	}

	if !v {
		t.Fatal("Signature not valid")
	}
}

package blind

import (
	"bytes"
	"fmt"
	"testing"
)

func TestBlind_RSAEncrypt(t *testing.T) {
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

func ExampleRSAConfig_Encrypt() {
	//	Standard RSA Encryption is RSA-OAEP. OAEP is parameterised by a hash function that is used as a random oracle.
	//	The message must be no longer than the length of the public modulus minus twice the hash length, minus a further 2.

	msg := []byte("The horse rides north at dawn ")
	label := []byte("Sent by grant")

	// Create a new Blind instance
	b, err := New()
	if err != nil {
		panic(err)
	}

	ct, err := b.RSA.Encrypt(msg, label)
	if err != nil {
		panic(err)
	}

	// To decrypt you must first export your Blind instance
	exjson := b.Export()
	im := Import(exjson)

	// Decrypt the data with the imported json keys and ct/label
	pt, err := im.RSA.Decrypt(ct, label)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(pt, msg) {
		panic("FAILED!")
	}

}

func TestBlind_RSASign(t *testing.T) {
	d := []byte("Hello, world")

	b, err := New()
	if err != nil {
		t.Fatal(err)
	}

	s, err := b.RSA.Sign(d)
	if err != nil {
		t.Fatal(err)
	}

	v, err := b.RSA.Verify(d, s)
	if err != nil {
		t.Fatal(err)
	}

	if !v {
		t.Fatal("Signature not valid")
	}
}

func ExampleRSAConfig_Sign() {
	// It is worth noting that blind is using PKCS1v15, which is deterministic, so don't use too small of a message here.
	// At some point I may switch this to use PSS.
	pt := []byte("my name is grant")

	// Create a new instance of Blind
	b, err := New()
	if err != nil {
		panic(err)
	}

	// Sign the text
	s, err := b.RSA.Sign(pt)
	if err != nil {
		panic(err)
	}

	fmt.Printf("The signature is %v\n", s)

	// Export to new instance
	ej := b.Export()
	im := Import(ej)

	// Verify the signature
	isVerified, err := im.RSA.Verify(pt, s)
	if err != nil {
		panic(err)
	}

	// This is a bool, true if it can be verified.
	if !isVerified {
		panic("Not verified")
	}
}

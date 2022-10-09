package blind

import (
	"bytes"
	"testing"
)

func TestAESCBCConfig_Encrypt(t *testing.T) {
	data := []byte("Hello, world!")

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := c.AES.CBC.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := c.AES.CBC.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, pt) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(data), string(pt))
	}
}

func TestAESCBCConfig_Layering(t *testing.T) {
	data := []byte("Hello, world!")

	c1, err := New()
	if err != nil {
		t.Fatal(err)
	}

	c2, err := New()
	if err != nil {
		t.Fatal(err)
	}

	c3, err := New()
	if err != nil {
		t.Fatal(err)
	}

	ct1, err := c1.AES.CBC.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := c2.AES.CBC.Encrypt(ct1)
	if err != nil {
		t.Fatal(err)
	}

	ct3, err := c3.AES.CBC.Encrypt(ct2)
	if err != nil {
		t.Fatal(err)
	}

	pt3, err := c3.AES.CBC.Decrypt(ct3)
	if err != nil {
		t.Fatal(err)
	}

	pt2, err := c2.AES.CBC.Decrypt(pt3)
	if err != nil {
		t.Fatal(err)
	}

	pt1, err := c1.AES.CBC.Decrypt(pt2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, pt1) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(data), string(pt1))
	}
}

func ExampleAESCBCConfig_Encrypt() {

	// For AES CBC encryption Blind uses a block size of 256 and PKCS7 padding
	pt := []byte("hello, world!")

	//	Initialize new blind object
	b, err := New()
	if err != nil {
		panic(err)
	}

	// Encrypt the data
	ct, err := b.AES.CBC.Encrypt(pt)
	if err != nil {
		panic(err)
	}

	// Export
	ej := b.Export()
	im := Import(ej)

	// Decrypt using imported keys
	pt2, err := im.AES.CBC.Decrypt(ct)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(pt, pt2) {
		panic("Message does not match")
	}

}

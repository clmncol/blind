package blind

import (
	"bytes"
	"testing"
)

func TestBlind_AESEncryptDecrypt(t *testing.T) {
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

func TestBlind_AESEncryptDecryptLayers(t *testing.T) {
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

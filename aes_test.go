package blind

import (
	"bytes"
	"testing"
)

func TestBlind_EncryptDecrypt(t *testing.T) {
	data := []byte("Hello, world!")

	c := NewAESConfig()
	ct := c.Encrypt(data)

	pt := c.Decrypt(ct)

	if bytes.Compare(data, pt) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(data), string(pt))
	}

}

func TestBlind_EncryptDecryptLayers(t *testing.T) {
	data := []byte("Hello, world!")

	c1 := NewAESConfig()
	c2 := NewAESConfig()
	c3 := NewAESConfig()

	ct1 := c1.Encrypt(data)
	ct2 := c2.Encrypt(ct1)
	ct3 := c3.Encrypt(ct2)

	pt3 := c3.Decrypt(ct3)
	pt2 := c2.Decrypt(pt3)
	pt1 := c1.Decrypt(pt2)

	if bytes.Compare(data, pt1) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(data), string(pt1))
	}

}

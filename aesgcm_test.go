package blind

import (
	"bytes"
	"testing"
)

func TestAESGCMConfig_Encrypt(t *testing.T) {
	ad := []byte("Sent by grant")
	pt := []byte("The horse rides north at dawn")

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := c.AES.GCM.Encrypt(pt, ad)
	if err != nil {
		t.Fatal(err)
	}

	pt2, err := c.AES.GCM.Decrypt(ct, ad)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, pt2) {
		t.Fatalf("'%v' not equal to '%v'", string(pt), string(pt2))
	}
}

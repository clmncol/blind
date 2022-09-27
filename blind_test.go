package blind

import (
	"bytes"
	"testing"
)

func TestBlind_ExportImport(t *testing.T) {
	data := []byte("Hello, world!")

	be, err := New()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := be.AES.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	e := be.Export()

	i := Import(e)

	pt, err := i.AES.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, pt) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(data), string(pt))
	}
}

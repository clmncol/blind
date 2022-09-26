package blind

import (
	"bytes"
	"testing"
)

func TestBlind_ExportImport(t *testing.T) {
	data := []byte("Hello, world!")

	be := New()
	ct := be.Encrypt(data)

	e := be.Export()

	i := Import(e)

	pt := i.Decrypt(ct)

	if bytes.Compare(data, pt) > 0 {
		t.Fatalf("'%v' not equal to '%v'", string(data), string(pt))
	}
}

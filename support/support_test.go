package blind

import (
	"bytes"
	"testing"
)

func TestBlind_PadUnpad(t *testing.T) {
	data := []byte("Hello, world!")
	p := PKCS7Pad(data)

	u := PKCS7Unpad(p)

	if bytes.Compare(data, u) > 0 {
		t.Fatalf("'%v' not '%v'", data, u)
	}
}

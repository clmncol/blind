package blind

import (
	"bytes"
	"math/big"
	"testing"
)

func TestXor(t *testing.T) {
	a := big.NewInt(99).Bytes()
	b := big.NewInt(98).Bytes()
	n := big.NewInt(1).Bytes()

	o, err := Xor(a, b)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(o, n) {
		t.Fatal("Error in XOR operation")
	}
}

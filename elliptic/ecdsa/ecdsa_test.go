package blind

import (
	"testing"

	support "github.com/Grant-Eckstein/blind/support"
)

func TestECDSA(t *testing.T) {
	// Create test message from random bytes of nonstandard length
	data, err := support.Bytes(30)
	if err != nil {
		t.Fatalf("Error generating bytes for testing: %v\n", err)
	}

	// Initialize the cipher
	e := NewECDSAConfig()

	// Sign the test message
	signature, err := e.Sign(data)
	if err != nil {
		t.Fatalf("Error signing test bytes: %v\n", err)
	}

	// Verify the test message's signature
	isCorrect, err := e.Verify(e, signature)
	if err != nil {
		t.Fatalf("Error verifying signature of test bytes: %v\n", err)
	}

	// If the signature is not correct something is wrong
	if !isCorrect {
		t.Fatal("Signature of test bytes could not be verified")
	}

}

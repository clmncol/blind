package kem

import (
	"bytes"
	"testing"
)

func Test_Shared(t *testing.T) {
	n1, err := New()
	if err != nil {
		t.Fatalf("unable to create new exchange n1: %s", err.Error())
	}

	n2, err := New()
	if err != nil {
		t.Fatalf("unable to create new exchange n2: %s", err.Error())
	}

	if bytes.Equal(n2.Public(), n1.Public()) {
		t.Fatal("two different instance public keys are equal")
	}

	/** n1 -> n2 **/
	// Generate a shared secret from n2's public key and send the required
	// ct to n2
	n2PublicKey := n2.Public()
	ct, n1ss := n1.Send(n2PublicKey)

	// generate shared secret from ct sent over open channel
	n2ss := n2.Receive(ct)

	/** verify **/
	if n1ss == nil || n2ss == nil {
		t.Fatal("shared key is nil")
	}

	if !bytes.Equal(n1ss, n2ss) {
		t.Fatal("shared keys are not equal")
	}
}

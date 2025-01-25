package dh

import (
	"bytes"
	"testing"
)

func Test_Shared(t *testing.T) {
	n1, err := New()
	if err != nil {
		t.Fatalf("unable to create new exchange key n1: %s", err.Error())
	}

	n2, err := New()
	if err != nil {
		t.Fatalf("unable to create new exchange key n2: %s", err.Error())
	}

	if len(n2.Public()) == 0 {
		e, err := n2.Export()
		if err != nil {
			t.Logf("unable to export n2: %s", err.Error())
		}
		t.Fatal("n2 private key is empty:\n", string(e))
	}

	// Exchange
	s1, err := n1.Shared(n2.Public())
	if err != nil {
		t.Fatalf("shared n1->n2 failed: %s", err.Error())
	}

	s2, err := n2.Shared(n1.Public())
	if err != nil {
		t.Fatalf("shared n2->n1 failed: %s", err.Error())
	}

	if !bytes.Equal(s1, s2) {
		t.Fatal("shared keys are not equal")
	}

	if len(s1) == 0 {
		t.Fatal("shared key is empty")
	}
}

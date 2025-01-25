package identity

import "testing"

func Test_Sign(t *testing.T) {
	data := []byte("Hello, world!")
	i, err := New()
	if err != nil {
		t.Fatalf("unable to initialize identity: %s", err.Error())
	}

	if _, err := i.Sign(data); err != nil {
		t.Fatalf("unable to sign data: %s", err.Error())
	}
}

func Test_verify(t *testing.T) {
	data := []byte("Hello, world!")
	i, err := New()
	if err != nil {
		t.Fatalf("unable to initialize identity: %s", err.Error())
	}

	// Sign data
	signature, err := i.Sign(data)
	if err != nil {
		t.Fatalf("unable to sign data: %s", err.Error())
	}

	// Verify signature of data
	if valid, err := i.Verify(data, signature); !valid {
		t.Fatal("signature is not valid")
	} else {
		if err != nil {
			t.Fatalf("signature is valid but err: %s", err.Error())
		}
	}
}

func Test_VerifyBadSig(t *testing.T) {
	data := []byte("Hello, world!")
	i, err := New()
	if err != nil {
		t.Fatalf("unable to initialize identity: %s", err.Error())
	}

	valid, _ := i.Verify(data, []byte("oops, I did it again!"))
	if valid {
		t.Fatal("invalid signature returned as valid")
	}
}

func Test_Import(t *testing.T) {
	i, err := New()
	if err != nil {
		t.Fatalf("unable to initialize identity: %s", err.Error())
	}

	e, err := i.Export()
	if err != nil {
		t.Fatalf("unable to generate export: %s", err.Error())
	}

	// import
	i2, err := New()
	if err != nil {
		t.Fatalf("unable to initialize second identity: %s", err.Error())
	}

	if err := i2.Import(e); err != nil {
		t.Fatalf("unable to import: %s", err.Error())
	}
}

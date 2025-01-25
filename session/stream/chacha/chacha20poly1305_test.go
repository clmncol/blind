package chacha

import "testing"

func Test_Encrypt(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("unable to get new session: %s", err.Error())
	}

	ad := []byte("Auth data")
	msg := []byte("data")
	ct, err := s.Encrypt(msg, ad)
	if err != nil {
		t.Fatalf("unable to encrypt: %s", err.Error())
	}

	_, err = s.Decrypt(ct, []byte("bad auth data"))
	if err == nil {
		t.Fatal("decrypt succeeded with bad auth data")
	}

	_, err = s.Decrypt(ct, ad)
	if err != nil {
		t.Fatalf("unable to decrypt: %s", err.Error())
	}
}

func Test_Export(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("unable to get new session: %s", err.Error())
	}

	if e, err := s.Export(); err != nil {
		t.Fatalf("unable to export: %s", err.Error())
	} else {
		// Import
		s2 := new(ChachaSession)
		if err := s2.Import(e); err != nil {
			t.Fatalf("unable to import: %s", err.Error())
		}
	}
}

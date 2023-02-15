package blind

import (
	"bytes"
	"encoding/hex"
	"testing"

	support "github.com/Grant-Eckstein/blind/support"
)

func TestAESCBCConfig_Encrypt(t *testing.T) {
	// Create test message from random bytes of nonstandard length
	data, err := support.Bytes(30)
	if err != nil {
		t.Fatalf("Error generating random bytes: %v\n", err)
	}

	// Initialize the cipher
	cipher := NewAESCBCConfig()

	// Encrypt the data with the cipher
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		t.Fatalf("Error encrypting data: %v\n", err)
	}

	// Decrypt the data with the cipher
	plaintext, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Error decrypting data: %v\n", err)
	}

	// If the decrypted data does not match the origional exactly, there is a problem
	if !bytes.Equal(data, plaintext) {
		t.Fatalf("'%v' not equal to '%v'\n", hex.EncodeToString(data),
			hex.EncodeToString(plaintext))
	}
}

func TestAESCBCConfig_Marshall(t *testing.T) {
	// Create test message from random bytes of nonstandard length
	data, err := support.Bytes(30)
	if err != nil {
		t.Fatalf("Error generating random bytes: %v\n", err)
	}

	// Initialize the cipher
	cipher := NewAESCBCConfig()

	// Export the cipher to bytes
	cipher_export, err := cipher.Marshall()
	if err != nil {
		t.Fatalf("Error exporting cipher: %v\n", err)
	}

	// Import the cipher bytes
	cipher_import := NewAESCBCConfig()
	err = cipher_import.Unmarshall(cipher_export)
	if err != nil {
		t.Fatalf("Error importing the exported cipher: %v\n", err)
	}

	// Encrypt the data with the imported cipher
	_, err = cipher_import.Encrypt(data)
	if err != nil {
		t.Fatalf("Error encrypting data with the imported cipher: %v\n", err)
	}
}

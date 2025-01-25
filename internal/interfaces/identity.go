package interfaces

import "errors"

type IdentityProvider interface {
	// Identity providers must be able to sign and verify a byte slice
	Sign([]byte) ([]byte, error)
	Verify(data []byte, signature []byte) (bool, error)

	// Identity providers must be exportable to a byte slice
	Export() ([]byte, error)
	Import([]byte) error
}

const (
	DilithiumIdentityType = 1
)

var (
	ErrWrongIdentityType = errors.New("wrong identity type")
)

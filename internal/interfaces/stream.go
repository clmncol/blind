package interfaces

type StreamSessionProvider interface {
	Provider

	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}

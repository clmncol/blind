package blind

type BlockCipherConfig interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	Marshall() ([]byte, error)
	Unmarshall([]byte) error
}

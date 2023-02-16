package blind

type Signature interface {
	Marshall() ([]byte, error)
	Unmarshall([]byte) error
}

type BlockCipherConfig interface {
	Sign([]byte) ([]byte, error)
	Verify(BlockCipherConfig, []byte) (bool, error)
	Marshall() ([]byte, error)
	Unmarshall([]byte) error
}

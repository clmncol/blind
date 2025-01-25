package interfaces

type Provider interface {
	// Export generates a byte slice copy of the entire object
	Export() ([]byte, error)

	// Import loads the entire object from a byte slice
	Import([]byte) error
}

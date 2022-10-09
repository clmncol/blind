package blind

type AESConfig struct {
	CBC AESCBCConfig
	GCM AESGCMConfig
}

func NewAESConfig() (AESConfig, error) {
	cbc, err := NewAESCBCConfig()
	if err != nil {
		return AESConfig{}, err
	}

	gcm, err := NewAESGCMConfig()
	if err != nil {
		return AESConfig{}, err
	}

	return AESConfig{
		CBC: cbc,
		GCM: gcm,
	}, nil
}

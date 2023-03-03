package blind

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

func Token(timeIncrementSeconds int, b64Key string) ([]byte, error) {
	// Assume that the key is given to us as a base64 encoded string
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}

	// Get the current time
	now := time.Now().UnixNano()

	// Counter is time since unix epoch
	counter := uint64(now/1000000000) / uint64(timeIncrementSeconds)

	// Convert counter to bytes
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, counter)

	// Calculate the HMAC hash of the counter and the secret key
	hash := hmac.New(sha256.New, key)
	hash.Write(counterBytes)
	hmacHash := hash.Sum(nil)

	// Truncate the hash to a 4 byte value
	offset := hmacHash[19] & 0x0f
	truncatedHash := (uint32(hmacHash[offset]) << 24) | (uint32(hmacHash[offset+1]) << 16) | (uint32(hmacHash[offset+2]) << 8) | uint32(hmacHash[offset+3])

	// Calculate the TOTP code, this will be 6 digits
	totp := truncatedHash % 1000000

	// Convert the TOTP code to bytes
	totpBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(totpBytes, totp)

	return totpBytes, nil
}

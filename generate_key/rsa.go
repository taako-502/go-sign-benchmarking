package generate_key

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func GenerateRSAKeyPair(bits int) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}
	return &privateKey.PublicKey, privateKey, nil
}

package generate_key

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	return publicKey, privateKey, nil
}

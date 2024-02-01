package generate_key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
)

func GenerateECDSAKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.New("ecdsa.GenerateKey")
	}
	return &privateKey.PublicKey, privateKey, nil
}

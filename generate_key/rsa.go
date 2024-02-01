package generate_key

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pkg/errors"
)

func GenerateRSAKeyPair(bits int) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, errors.Wrap(err, "rsa.GenerateKey")
	}
	return &privateKey.PublicKey, privateKey, nil
}

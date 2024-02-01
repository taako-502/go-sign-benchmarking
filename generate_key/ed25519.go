package generate_key

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/pkg/errors"
)

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ed25519.GenerateKey")
	}
	return publicKey, privateKey, nil
}

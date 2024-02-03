package sign_benchmark

import "github.com/golang-jwt/jwt/v5"

type signReciever struct {
	secretKey     interface{}
	encryptionKey interface{}
	method        jwt.SigningMethod
}

func NewSignReciever(secretKey interface{}, encryptionKey interface{}, method jwt.SigningMethod) signReciever {
	return signReciever{
		secretKey:     secretKey,
		encryptionKey: encryptionKey,
		method:        method,
	}
}

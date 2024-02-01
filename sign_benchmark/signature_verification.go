package sign_benchmark

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

func (s signReciever) SignatureVerification(method jwt.SigningMethod, iterations int) (time.Duration, error) {
	// まず署名されたトークンを生成
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"name": "John Doe",
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
	})

	signedToken, err := token.SignedString(s.secretKey)
	if err != nil {
		return 0, errors.Wrap(err, "jwt.Token.SignedString")
	}

	// 生成したトークンを指定された回数だけ検証
	startTime := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
			if token.Method != method {
				return nil, errors.New("不正な署名方法")
			}
			// RSAまたはRSA-PSSの場合は公開鍵を使用
			switch token.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
				if publicKey, ok := s.encryptionKey.(*rsa.PublicKey); ok {
					return publicKey, nil
				}
				return nil, errors.New("不適切な公開鍵の型")
			// ECDSAの場合は公開鍵を使用
			case *jwt.SigningMethodECDSA:
				if publicKey, ok := s.encryptionKey.(*ecdsa.PublicKey); ok {
					return publicKey, nil
				}
				return nil, errors.New("不適切な公開鍵の型")
			// Ed25519の場合は公開鍵を使用
			case *jwt.SigningMethodEd25519:
				return s.encryptionKey, nil
			}
			return s.secretKey, nil
		})

		if err != nil {
			return 0, errors.Wrap(err, "jwt.Parse")
		}
	}
	endTime := time.Now()

	duration := endTime.Sub(startTime)
	return duration, nil
}

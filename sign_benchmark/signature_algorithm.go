package sign_benchmark

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (s signReciever) SignatureAlgorithm(iterations int) (time.Duration, error) {
	startTime := time.Now()
	for i := 0; i < iterations; i++ {
		token := jwt.NewWithClaims(s.method, jwt.MapClaims{
			"name": "John Doe",
			"exp":  time.Now().Add(time.Hour * 72).Unix(),
		})

		if _, err := token.SignedString(s.secretKey); err != nil {
			return 0, fmt.Errorf("jwt.Token.SignedString: %w", err)
		}
	}
	endTime := time.Now()

	duration := endTime.Sub(startTime)
	return duration, nil
}

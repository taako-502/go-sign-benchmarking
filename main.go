package main

import (
	"fmt"
	"go-sign-benchmarking/generate_key"
	"go-sign-benchmarking/sign_benchmark"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

const ITERATIONS = 10000

type algorithm struct {
	secretKey interface{}
	label     string
	method    jwt.SigningMethod
}

func main() {
	algorithms, err := buildAlgorithms()
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, method := range algorithms {
		s := sign_benchmark.NewSignReciever(method.secretKey)
		duration, err := s.SignatureAlgorithm(method.method, ITERATIONS)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("")
		fmt.Printf("## %s\r\n", method.label)
		milliseconds := float64(duration) / float64(time.Millisecond)
		fmt.Printf("JWT署名生成（10,000回）にかかった時間: %.3f ms\n", milliseconds)
	}

	fmt.Println("")
	fmt.Println("終了")
}

func buildAlgorithms() ([]algorithm, error) {
	var algorithms []algorithm
	// HS256
	secretKey, err := generate_key.GenerateHS256Key()
	if err != nil {
		return nil, errors.Wrap(err, "generate_key.GenerateHS256Key")
	}
	algorithms = append(algorithms, algorithm{secretKey: secretKey, label: "HS256", method: jwt.SigningMethodHS256})

	// Ed25519
	_, privateKey, err := generate_key.GenerateEd25519KeyPair()
	if err != nil {
		return nil, errors.Wrap(err, "generate_key.GenerateEd25519KeyPair")
	}
	algorithms = append(algorithms, algorithm{secretKey: privateKey, label: "Ed25519", method: &jwt.SigningMethodEd25519{}})

	// RS256
	_, rsaPrivateKey, err := generate_key.GenerateRSAKeyPair(2048) // 通常は2048または4096
	if err != nil {
		return nil, errors.Wrap(err, "generate_key.GenerateRSAKeyPair")
	}
	algorithms = append(algorithms, algorithm{secretKey: rsaPrivateKey, label: "RS256", method: jwt.SigningMethodRS256})

	// ES256
	_, ecdsaPrivateKey, err := generate_key.GenerateECDSAKeyPair()
	if err != nil {
		return nil, errors.Wrap(err, "generate_key.GenerateECDSAKeyPair")
	}
	algorithms = append(algorithms, algorithm{secretKey: ecdsaPrivateKey, label: "ES256", method: jwt.SigningMethodES256})

	// PS256
	algorithms = append(algorithms, algorithm{secretKey: rsaPrivateKey, label: "PS256", method: jwt.SigningMethodPS256})

	return algorithms, nil
}

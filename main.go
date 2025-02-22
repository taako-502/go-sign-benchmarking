package main

import (
	"fmt"
	"go-sign-benchmarking/generate_key"
	"go-sign-benchmarking/sign_benchmark"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type algorithm struct {
	secretKey     interface{}
	encryptionKey interface{}
	label         string
	method        jwt.SigningMethod
}

func newAlgorithm(secretKey interface{}, encryptionKey interface{}, label string, method jwt.SigningMethod) algorithm {
	return algorithm{
		secretKey:     secretKey,
		encryptionKey: encryptionKey,
		label:         label,
		method:        method,
	}
}

func main() {
	algorithms, err := buildAlgorithms()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("・〜・〜・〜・〜・〜・〜署名の作成速度の測定・〜・〜・〜・〜・〜・〜")
	for _, method := range algorithms {
		s := sign_benchmark.NewSignReciever(method.secretKey, nil, method.method)
		duration, err := s.SignatureAlgorithm(10000)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("")
		fmt.Printf("## %s\r\n", method.label)
		milliseconds := float64(duration) / float64(time.Millisecond)
		fmt.Printf("JWT署名生成（10,000回）にかかった時間: %.3f ms\n", milliseconds)
	}

	fmt.Println("・〜・〜・〜・〜・〜・〜署名の検証速度の測定・〜・〜・〜・〜・〜・〜")
	for _, a := range algorithms {
		fmt.Println("")
		fmt.Printf("## %s\r\n", a.label)
		s := sign_benchmark.NewSignReciever(a.secretKey, a.encryptionKey, a.method)
		duration, err := s.SignatureVerification(10000)
		if err != nil {
			fmt.Println(err)
			return
		}
		milliseconds := float64(duration) / float64(time.Millisecond)
		fmt.Printf("JWT署名検証（10,000回）にかかった時間: %.3f ms\n", milliseconds)
	}

	fmt.Println("")
	fmt.Println("終了")
}

func buildAlgorithms() ([]algorithm, error) {
	var algorithms []algorithm
	// HS256
	secretKey, err := generate_key.GenerateHS256Key()
	if err != nil {
		return nil, fmt.Errorf("generate_key.GenerateHS256Key: %w", err)
	}
	algorithms = append(algorithms,
		newAlgorithm(secretKey, secretKey, "HS256", jwt.SigningMethodHS256),
	)

	// Ed25519
	publickKey, privateKey, err := generate_key.GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate_key.GenerateEd25519KeyPair: %w", err)
	}
	algorithms = append(algorithms,
		newAlgorithm(privateKey, publickKey, "Ed25519", &jwt.SigningMethodEd25519{}),
	)

	// RS256
	rsaPublicKey, rsaPrivateKey, err := generate_key.GenerateRSAKeyPair(2048) // 通常は2048または4096
	if err != nil {
		return nil, fmt.Errorf("generate_key.GenerateRSAKeyPair: %w", err)
	}
	algorithms = append(algorithms,
		newAlgorithm(rsaPrivateKey, rsaPublicKey, "RS256", jwt.SigningMethodRS256),
	)

	// ES256
	ecdsaPublicKey, ecdsaPrivateKey, err := generate_key.GenerateECDSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate_key.GenerateECDSAKeyPair: %w", err)
	}
	algorithms = append(algorithms,
		newAlgorithm(ecdsaPrivateKey, ecdsaPublicKey, "ES256", jwt.SigningMethodES256),
	)

	// PS256
	algorithms = append(algorithms,
		newAlgorithm(rsaPrivateKey, rsaPublicKey, "PS256", jwt.SigningMethodPS256),
	)

	return algorithms, nil
}

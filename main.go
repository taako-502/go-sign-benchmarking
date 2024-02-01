package main

import (
	"fmt"
	"go-sign-benchmarking/generate_key"
	"go-sign-benchmarking/sign_benchmark"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const ITERATIONS = 10000

func main() {
	fmt.Println("# 対称鍵署名アルゴリズム")
	fmt.Println("## HS256")
	s := sign_benchmark.NewSymmetricKeyReciever([]byte("your-secret-key"))
	duration, err := s.SymmetricKeySignatureAlgorithm(jwt.SigningMethodHS256, ITERATIONS)
	if err != nil {
		fmt.Println(err)
		return
	}
	printDuration(duration)

	fmt.Println("◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎")
	fmt.Println("# 非対称鍵署名アルゴリズム")
	fmt.Println("## Ed25519")
	_, privateKey, err := generate_key.GenerateEd25519KeyPair()
	if err != nil {
		fmt.Println(err)
		return
	}
	a := sign_benchmark.NewAsymmetricKeyReciever(privateKey, []byte(""))
	duration, err = a.AsymmetricKeySignatureAlgorithm(&jwt.SigningMethodEd25519{}, ITERATIONS)
	if err != nil {
		fmt.Println(err)
		return
	}
	printDuration(duration)

	fmt.Println("◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎")
	fmt.Println("## RS256")
	_, rsaPrivateKey, err := generate_key.GenerateRSAKeyPair(2048) // 通常は2048または4096
	if err != nil {
		fmt.Println(err)
		return
	}
	a = sign_benchmark.NewAsymmetricKeyReciever(rsaPrivateKey, []byte(""))
	duration, err = a.AsymmetricKeySignatureAlgorithm(jwt.SigningMethodRS256, ITERATIONS)
	if err != nil {
		fmt.Println(err)
		return
	}
	printDuration(duration)

	fmt.Println("◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎")
	fmt.Println("## ES256")
	_, ecdsaPrivateKey, err := generate_key.GenerateECDSAKeyPair()
	if err != nil {
		fmt.Println(err)
		return
	}
	a = sign_benchmark.NewAsymmetricKeyReciever(ecdsaPrivateKey, []byte(""))
	duration, err = a.AsymmetricKeySignatureAlgorithm(jwt.SigningMethodES256, ITERATIONS)
	if err != nil {
		fmt.Println(err)
		return
	}
	printDuration(duration)

	fmt.Println("◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎◻︎◾︎")
	fmt.Println("## PS256")
	a = sign_benchmark.NewAsymmetricKeyReciever(rsaPrivateKey, []byte("")) // RS256と同じ鍵を使う
	duration, err = a.AsymmetricKeySignatureAlgorithm(jwt.SigningMethodPS256, ITERATIONS)
	if err != nil {
		fmt.Println(err)
		return
	}
	printDuration(duration)
}

func printDuration(duration time.Duration) {
	milliseconds := float64(duration) / float64(time.Millisecond)
	fmt.Printf("JWT署名生成（10,000回）にかかった時間: %.3f ms\n", milliseconds)
}

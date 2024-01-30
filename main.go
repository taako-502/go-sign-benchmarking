package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func main() {
	// JWT署名のための秘密鍵
	secretKey := []byte("your-secret-key")

	// 署名を10,000回繰り返す
	startTime := time.Now()
	for i := 0; i < 10000; i++ {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"name": "John Doe",
			"exp":  time.Now().Add(time.Hour * 72).Unix(),
		})

		// トークンに署名を追加
		_, err := token.SignedString(secretKey)
		if err != nil {
			fmt.Printf("トークンの署名に失敗しました: %v\n", err)
			return
		}
	}
	endTime := time.Now()

	// 処理にかかった時間を計算し、表示
	duration := endTime.Sub(startTime)
	fmt.Printf("JWT署名生成（10,000回）にかかった時間: %v\n", duration)
}

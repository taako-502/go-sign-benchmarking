package generate_key

import (
	"crypto/rand"
	"fmt"
)

// GenerateHS256Key はHS256アルゴリズム用の共通鍵を生成します。
func GenerateHS256Key() ([]byte, error) {
	key := make([]byte, 32) // 32バイト（256ビット）の鍵
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	return key, nil
}

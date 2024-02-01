package generate_key

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

// GenerateHS256Key はHS256アルゴリズム用の共通鍵を生成します。
func GenerateHS256Key() ([]byte, error) {
	key := make([]byte, 32) // 32バイト（256ビット）の鍵
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "rand.Read")
	}
	return key, nil
}

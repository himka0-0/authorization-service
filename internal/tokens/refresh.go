package tokens

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomBase64(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

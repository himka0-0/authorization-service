package tokens

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type Jwt struct {
	secretKey string
	tokentime time.Duration
}

func NewJwt(secretKey string, tokentime time.Duration) *Jwt {
	return &Jwt{secretKey, tokentime}
}

func (m *Jwt) GenerateToken(userGUID string, refreshID string) (string, error) {
	claims := jwt.MapClaims{
		"guid":      userGUID,
		"refreshID": refreshID,
		"exp":       time.Now().Add(m.tokentime).Unix(),
		"iat":       time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(m.secretKey))
}

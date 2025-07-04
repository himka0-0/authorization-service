package tokens

import (
	"fmt"
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
		"guid":       userGUID,
		"refresh_id": refreshID,
		"exp":        time.Now().Add(m.tokentime).Unix(),
		"iat":        time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(m.secretKey))
}

func (m *Jwt) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	return claims, nil
}

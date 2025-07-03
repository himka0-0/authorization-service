package service

import (
	"MEDODS/internal/repository"
	"MEDODS/internal/tokens"
)

type AuthService struct {
	jwt         *tokens.Jwt
	refreshRepo *repository.RefreshTokenRepo
}

func NewAuthService(j *tokens.Jwt, r *repository.RefreshTokenRepo) *AuthService {
	return &AuthService{
		jwt:         j,
		refreshRepo: r,
	}
}

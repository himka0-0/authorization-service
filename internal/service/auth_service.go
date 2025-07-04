package service

import (
	"MEDODS/internal/model"
	"MEDODS/internal/repository"
	"MEDODS/internal/tokens"
)

type AuthService struct {
	jwt         *tokens.Jwt
	refreshRepo *repository.RefreshTokenRepo
}

func (s *AuthService) VerifyAccessToken(token string) (map[string]interface{}, error) {
	return s.jwt.VerifyToken(token)
}

func (s *AuthService) GetRefreshToken(refreshID string) (*model.RefreshToken, error) {
	return s.refreshRepo.GetByID(refreshID)
}

func (s *AuthService) DeauthorizeUser(guid string) error {
	return s.refreshRepo.DeleteAllByUserGUID(guid)
}

func NewAuthService(j *tokens.Jwt, r *repository.RefreshTokenRepo) *AuthService {
	return &AuthService{
		jwt:         j,
		refreshRepo: r,
	}
}

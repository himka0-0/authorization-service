package service

import (
	"MEDODS/internal/model"
	"MEDODS/internal/repository"
	"MEDODS/internal/tokens"
	"MEDODS/internal/util"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type AuthService struct {
	jwt         *tokens.Jwt
	refreshRepo *repository.RefreshTokenRepo
}
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func NewAuthService(j *tokens.Jwt, r *repository.RefreshTokenRepo) *AuthService {
	return &AuthService{
		jwt:         j,
		refreshRepo: r,
	}
}
func (s *AuthService) IssueTokens(userGUID, userAgent, ip string) (*TokenPair, error) {
	// Generate Access Token
	access, err := s.jwt.GenerateToken(userGUID)
	if err != nil {
		return nil, err
	}

	// Generate Refresh Token
	refreshRaw, err := tokens.GenerateRandomBase64(32)
	if err != nil {
		return nil, err
	}

	// Hash refresh token with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshRaw), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Save hashed refresh token
	rt := &model.RefreshToken{
		ID:        util.GenerateUUID(),
		UserGUID:  userGUID,
		Hash:      string(hash),
		UserAgent: userAgent,
		IP:        ip,
		Used:      false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	if err := s.refreshRepo.Save(rt); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refreshRaw,
	}, nil
}

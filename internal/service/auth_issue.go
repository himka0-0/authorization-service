package service

import (
	"MEDODS/internal/model"
	"MEDODS/internal/tokens"
	"MEDODS/internal/util"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (s *AuthService) IssueTokens(userGUID, userAgent, ip string) (*TokenPair, error) {
	refreshRaw, err := tokens.GenerateRandomBase64(32)
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshRaw), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

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

	access, err := s.jwt.GenerateToken(userGUID, rt.ID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refreshRaw,
	}, nil
}

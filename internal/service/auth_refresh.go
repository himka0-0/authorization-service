package service

import (
	"MEDODS/internal/model"
	"MEDODS/internal/util"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func (s *AuthService) RefreshTokens(accessToken, refreshtoken, UserAgent, ip string) (*TokenPair, error) {
	_, issuedAt, refreshID, guid, err := s.parseClaims(accessToken)
	if err != nil {
		return nil, err
	}

	dataRefreshtoken, err := s.refreshRepo.GetByID(refreshID)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %v", err)
	}

	if err := s.validateRefreshToken(dataRefreshtoken, refreshtoken, guid, issuedAt, UserAgent, ip); err != nil {
		return nil, err
	}

	if err := s.refreshRepo.ChangUsage(refreshID); err != nil {
		return nil, err
	}
	return s.IssueTokens(dataRefreshtoken.UserGUID, UserAgent, ip)
}

func (s *AuthService) parseClaims(token string) (claims map[string]interface{}, issuedAt time.Time, refreshID, guid string, err error) {
	parsedClaims, err := s.jwt.VerifyToken(token)
	if err != nil {
		return nil, time.Time{}, "", "", fmt.Errorf("invalid access token: %v", err)
	}

	guidValue, ok := parsedClaims["guid"].(string)
	if !ok || guidValue == "" {
		return nil, time.Time{}, "", "", fmt.Errorf("guid missing in token")
	}

	refreshIDValue, ok := parsedClaims["refresh_id"].(string)
	if !ok || refreshIDValue == "" {
		return nil, time.Time{}, "", "", fmt.Errorf("refresh_id missing in token")
	}

	iatFloat, ok := parsedClaims["iat"].(float64)
	if !ok {
		return nil, time.Time{}, "", "", fmt.Errorf("iat missing in token")
	}
	issuedAt = time.Unix(int64(iatFloat), 0)

	return parsedClaims, issuedAt, refreshIDValue, guidValue, nil
}

func (s *AuthService) validateRefreshToken(token *model.RefreshToken, refreshToken, guid string, issuedAt time.Time, userAgent, ip string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(token.Hash), []byte(refreshToken)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return fmt.Errorf("invalid refresh token")
		}
		return err
	}

	if util.AbsDuration(token.CreatedAt.Sub(issuedAt)) > 5*time.Second {
		return fmt.Errorf("tokens were not issued together")
	}

	if token.UserGUID != guid {
		return fmt.Errorf("invalid token: user mismatch")
	}

	if token.UserAgent != userAgent {
		if err := s.refreshRepo.DeleteAllByUserGUID(token.UserGUID); err != nil {
			return fmt.Errorf("failed to delete token on user agent mismatch: %v", err)
		}
		return fmt.Errorf("user agent mismatch")
	}

	if token.IP != ip {
		go s.sendWebhook(token.IP, token.UserGUID)
	}

	if token.Used {
		return fmt.Errorf("token already used")
	}

	return nil
}

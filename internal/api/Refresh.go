package api

import (
	"MEDODS/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

type RefreshHandler struct {
	authService *service.AuthService
}

func NewRefreshHandler(s *service.AuthService) *RefreshHandler {
	return &RefreshHandler{authService: s}
}

type ReqRefresh struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func (h *RefreshHandler) Refresh(c *gin.Context) {
	var input ReqRefresh
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if input.AccessToken == "" || input.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "access_token or refresh_token is required"})
		return
	}
	tokens, err := h.authService.RefreshTokens(
		input.AccessToken,
		input.RefreshToken,
		c.Request.UserAgent(),
		c.ClientIP(),
	)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

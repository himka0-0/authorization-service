package api

import (
	"MEDODS/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

type LoginHandler struct {
	authService *service.AuthService
}

func NewLoginHandler(s *service.AuthService) *LoginHandler {
	return &LoginHandler{authService: s}
}

func (h *LoginHandler) Login(c *gin.Context) {
	guid := c.Param("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GUID is required"})
		return
	}

	tokens, err := h.authService.IssueTokens(
		guid,
		c.Request.UserAgent(),
		c.ClientIP(),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

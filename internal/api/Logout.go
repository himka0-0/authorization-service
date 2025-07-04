package api

import (
	"MEDODS/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
)

type LogoutHandler struct {
	authService *service.AuthService
}

func NewLogoutHandler(s *service.AuthService) *LogoutHandler {
	return &LogoutHandler{
		authService: s,
	}
}
func (h *LogoutHandler) Logout(c *gin.Context) {
	guid := c.GetString("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GUID is required"})
		return
	}
	if err := h.authService.DeauthorizeUser(guid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deauthorize"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user deauthorized successfully"})
}

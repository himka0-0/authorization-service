package middleware

import (
	"MEDODS/internal/service"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func AuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header missing"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		claims, err := authService.VerifyAccessToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": "invalid or expired access token"})
			c.Abort()
			return
		}

		guid, ok := claims["guid"].(string)
		if !ok || guid == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}

		refreshID, ok := claims["refresh_id"].(string)
		if ok && refreshID != "" {
			tokenRecord, err := authService.GetRefreshToken(refreshID)
			if err != nil {
				c.JSON(401, gin.H{"error": "refresh token not found"})
				c.Abort()
				return
			}
			if tokenRecord.Used {
				c.JSON(401, gin.H{"error": "refresh token already used"})
				c.Abort()
				return
			}
		}

		c.Set("guid", guid)
		c.Next()
	}
}

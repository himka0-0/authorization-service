package api_test

import (
	"MEDODS/internal/api"
	"MEDODS/internal/middleware"
	"MEDODS/internal/model"
	"MEDODS/internal/repository"
	"MEDODS/internal/service"
	"MEDODS/internal/tokens"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLogoutHandler_GoodResult(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewLogoutHandler(authService)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("some-refresh"), bcrypt.DefaultCost)
	db.Create(&model.RefreshToken{
		ID:        "refresh-1",
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})

	db.Create(&model.RefreshToken{
		ID:        "refresh-2",
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})

	access, err := jwtManager.GenerateToken("1234", "refresh-1")
	require.NoError(t, err)

	r := gin.Default()
	r.POST("/logout",
		middleware.AuthMiddleware(authService),
		handler.Logout,
	)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer "+access)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "deauthorized")

	var count int64
	db.Model(&model.RefreshToken{}).Where("user_guid = ?", "1234").Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestLogoutHandler_NoAuthorization(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewLogoutHandler(authService)

	r := gin.Default()
	r.POST("/logout",
		middleware.AuthMiddleware(authService),
		handler.Logout,
	)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authorization header missing")
}

func TestLogoutHandler_InvalidToken(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewLogoutHandler(authService)

	r := gin.Default()
	r.POST("/logout",
		middleware.AuthMiddleware(authService),
		handler.Logout,
	)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired access token")
}

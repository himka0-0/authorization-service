package api_test

import (
	"MEDODS/internal/api"
	"MEDODS/internal/repository"
	"MEDODS/internal/service"
	"MEDODS/internal/tokens"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginHandler_Login(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	assert.NoError(t, err)

	err = db.AutoMigrate(&repository.RefreshTokenRepo{})
	assert.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewLoginHandler(authService)

	r := gin.Default()
	r.GET("/login/user/:guid", handler.Login)

	req := httptest.NewRequest(http.MethodGet, "/login/user/1234", nil)
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.Contains(t, body, "access_token")
	assert.Contains(t, body, "refresh_token")
}

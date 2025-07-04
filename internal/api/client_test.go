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

func TestClientHandler_MyGuid_GoodResult(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	clientHandler := api.MyGuid

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("stub"), bcrypt.DefaultCost)
	db.Create(&model.RefreshToken{
		ID:        "refresh-id",
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	access, err := jwtManager.GenerateToken("1234", "refresh-id")
	require.NoError(t, err)

	r := gin.Default()
	r.GET("/myguid",
		middleware.AuthMiddleware(authService),
		clientHandler,
	)

	req := httptest.NewRequest(http.MethodGet, "/myguid", nil)
	req.Header.Set("Authorization", "Bearer "+access)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"guid":"1234"`)
}

func TestClientHandler_MyGuid_NoAuthorization(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)

	r := gin.Default()
	r.GET("/myguid",
		middleware.AuthMiddleware(authService),
		api.MyGuid,
	)

	req := httptest.NewRequest(http.MethodGet, "/myguid", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authorization header missing")
}

func TestClientHandler_MyGuid_InvalidHeaderFormat(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)

	r := gin.Default()
	r.GET("/myguid",
		middleware.AuthMiddleware(authService),
		api.MyGuid,
	)

	req := httptest.NewRequest(http.MethodGet, "/myguid", nil)
	req.Header.Set("Authorization", "BadFormatTokenHere")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid authorization header format")
}

func TestClientHandler_MyGuid_InvalidToken(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)

	r := gin.Default()
	r.GET("/myguid",
		middleware.AuthMiddleware(authService),
		api.MyGuid,
	)

	req := httptest.NewRequest(http.MethodGet, "/myguid", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired access token")
}

func TestClientHandler_MyGuid_ExpiredToken(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	expiredJWT := tokens.NewJwt("test_secret", -1*time.Hour) // уже истёк
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(expiredJWT, repo)

	r := gin.Default()
	r.GET("/myguid",
		middleware.AuthMiddleware(authService),
		api.MyGuid,
	)

	access, err := expiredJWT.GenerateToken("1234", "refresh-id")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/myguid", nil)
	req.Header.Set("Authorization", "Bearer "+access)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "expired")
}

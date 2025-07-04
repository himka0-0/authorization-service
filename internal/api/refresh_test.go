package api_test

import (
	"MEDODS/internal/api"
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
	"strings"
	"testing"
	"time"
)

func TestRefreshHandler_Refresh_GoodResult(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewRefreshHandler(authService)

	rawRefresh := "somerandomstring"
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawRefresh), bcrypt.DefaultCost)
	require.NoError(t, err)

	refreshID := "test-refresh-id"
	createdAt := time.Now()

	tokenModel := &model.RefreshToken{
		ID:        refreshID,
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}

	err = db.Create(tokenModel).Error
	require.NoError(t, err)

	access, err := jwtManager.GenerateToken("1234", refreshID)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	body := `{"access_token":"` + access + `","refresh_token":"` + rawRefresh + `"}`

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusOK, w.Code)

	assert.Contains(t, w.Body.String(), "access_token")
	assert.Contains(t, w.Body.String(), "refresh_token")

	var tokenInDB model.RefreshToken
	err = db.First(&tokenInDB, "id = ?", refreshID).Error
	require.NoError(t, err)
	assert.True(t, tokenInDB.Used)
}

func TestRefreshHandler_UsedToken(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewRefreshHandler(authService)

	rawRefresh := "somerandomstring"
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawRefresh), bcrypt.DefaultCost)
	require.NoError(t, err)

	refreshID := "used-token-id"
	createdAt := time.Now()

	tokenModel := &model.RefreshToken{
		ID:        refreshID,
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      true,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}
	err = db.Create(tokenModel).Error
	require.NoError(t, err)

	access, err := jwtManager.GenerateToken("1234", refreshID)
	require.NoError(t, err)

	body := `{"access_token":"` + access + `","refresh_token":"` + rawRefresh + `"}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Contains(t, w.Body.String(), "already used")
}

func TestRefreshHandler_WrongRefreshToken(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewRefreshHandler(authService)

	rawRefresh := "correct-refresh-token"
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawRefresh), bcrypt.DefaultCost)
	require.NoError(t, err)

	refreshID := "wrong-refresh-id"
	createdAt := time.Now()

	tokenModel := &model.RefreshToken{
		ID:        refreshID,
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}
	err = db.Create(tokenModel).Error
	require.NoError(t, err)

	access, err := jwtManager.GenerateToken("1234", refreshID)
	require.NoError(t, err)

	body := `{"access_token":"` + access + `","refresh_token":"invalid-token"}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Contains(t, w.Body.String(), "invalid refresh token")
}

func TestRefreshHandler_UserAgentMismatch(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewRefreshHandler(authService)

	rawRefresh := "useragent-refresh-token"
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawRefresh), bcrypt.DefaultCost)
	require.NoError(t, err)

	refreshID := "ua-mismatch-id"
	createdAt := time.Now()

	tokenModel := &model.RefreshToken{
		ID:        refreshID,
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}
	err = db.Create(tokenModel).Error
	require.NoError(t, err)

	access, err := jwtManager.GenerateToken("1234", refreshID)
	require.NoError(t, err)

	body := `{"access_token":"` + access + `","refresh_token":"` + rawRefresh + `"}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DifferentAgent") // <-- ВАЖНО!
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Contains(t, w.Body.String(), "user agent mismatch")

	var count int64
	err = db.Model(&model.RefreshToken{}).Where("user_guid = ?", "1234").Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "Все токены пользователя должны быть удалены")
}

func TestRefreshHandler_MissingTokens(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewRefreshHandler(authService)

	body := `{}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	assert.Contains(t, w.Body.String(), "required")
}

func TestRefreshHandler_ExpiredAccessToken(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	expiredJWT := tokens.NewJwt("test_secret", -1*time.Hour)

	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(expiredJWT, repo)
	handler := api.NewRefreshHandler(authService)

	rawRefresh := "expired-refresh-token"
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawRefresh), bcrypt.DefaultCost)
	require.NoError(t, err)

	refreshID := "expired-refresh-id"
	createdAt := time.Now().Add(-2 * time.Hour) // Чтобы время точно было в прошлом

	tokenModel := &model.RefreshToken{
		ID:        refreshID,
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}
	err = db.Create(tokenModel).Error
	require.NoError(t, err)

	access, err := expiredJWT.GenerateToken("1234", refreshID)
	require.NoError(t, err)

	body := `{"access_token":"` + access + `","refresh_token":"` + rawRefresh + `"}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Contains(t, w.Body.String(), "expired")
}

func TestRefreshHandler_NotIssuedTogether(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&model.RefreshToken{})
	require.NoError(t, err)

	jwtManager := tokens.NewJwt("test_secret", time.Hour)
	repo := repository.NewRefreshTokenRepo(db)
	authService := service.NewAuthService(jwtManager, repo)
	handler := api.NewRefreshHandler(authService)

	rawRefresh := "not-together-refresh"
	hashed, err := bcrypt.GenerateFromPassword([]byte(rawRefresh), bcrypt.DefaultCost)
	require.NoError(t, err)

	refreshID := "not-together-id"
	createdAt := time.Now().Add(-2 * time.Hour)

	tokenModel := &model.RefreshToken{
		ID:        refreshID,
		UserGUID:  "1234",
		Hash:      string(hashed),
		UserAgent: "TestAgent",
		IP:        "1.2.3.4",
		Used:      false,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(30 * 24 * time.Hour),
	}
	err = db.Create(tokenModel).Error
	require.NoError(t, err)

	access, err := jwtManager.GenerateToken("1234", refreshID)
	require.NoError(t, err)

	body := `{"access_token":"` + access + `","refresh_token":"` + rawRefresh + `"}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestAgent")
	req.RemoteAddr = "1.2.3.4:56789"

	c.Request = req

	handler.Refresh(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Contains(t, w.Body.String(), "not issued together")
}

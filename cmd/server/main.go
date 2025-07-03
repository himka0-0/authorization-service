package main

import (
	"MEDODS/internal/api"
	"MEDODS/internal/db"
	"MEDODS/internal/repository"
	"MEDODS/internal/service"
	"MEDODS/internal/tokens"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"log"
	"os"
	"time"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Ошибка загрузки .env файла")
	}
	database := db.InitDB()

	jwtManager := tokens.NewJwt(os.Getenv("JWT_SECRET"), time.Hour)

	repo := repository.NewRefreshTokenRepo(database)

	authService := service.NewAuthService(jwtManager, repo)

	r := gin.Default()

	r.GET("/login/user/:guid", api.NewLoginHandler(authService).Login)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

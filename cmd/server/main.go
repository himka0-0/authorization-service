package main

import (
	"MEDODS/internal/api"
	"MEDODS/internal/db"
	"MEDODS/internal/middleware"
	"MEDODS/internal/repository"
	"MEDODS/internal/service"
	"MEDODS/internal/tokens"
	"github.com/gin-contrib/cors"
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

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	r.GET("/login/user/:guid", api.NewLoginHandler(authService).Login)
	r.POST("/refresh", api.NewRefreshHandler(authService).Refresh)
	r.GET("/myguid", middleware.AuthMiddleware(authService), api.MyGuid)
	r.POST("/logout", middleware.AuthMiddleware(authService), api.NewLogoutHandler(authService).Logout)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

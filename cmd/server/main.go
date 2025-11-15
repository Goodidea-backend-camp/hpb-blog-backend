package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/api"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/auth"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/middleware"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/repository"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	errDatabaseURLNotSet   = errors.New("DATABASE_URL environment variable is not set")
	errBackendDomainNotSet = errors.New("BACKEND_DOMAIN environment variable must be set")
)

func run() error {
	databaseUrl := os.Getenv("DATABASE_URL")
	if databaseUrl == "" {
		return errDatabaseURLNotSet
	}

	dbpool, err := pgxpool.New(context.Background(), databaseUrl)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %w", err)
	}
	defer dbpool.Close()

	if err := dbpool.Ping(context.Background()); err != nil {
		return fmt.Errorf("unable to ping database: %w", err)
	}

	log.Println("Successfully connected to the database!")

	// 初始化 DB Queries 和 Store
	queries := db.New(dbpool)
	postStore := store.NewPostStore(queries)
	authRepo := repository.NewAuthRepository(queries)

	// 初始化 Handler
	handler := api.NewHandler(postStore)

	// 從 .env 取得 JWT secret 並驗證
	jwtSecret := os.Getenv("JWT_SECRET")
	if err := auth.ValidateSecret(jwtSecret); err != nil {
		return fmt.Errorf("invalid JWT secret: %w", err)
	}

	// 初始化 AuthHandler
	authHandler, err := api.NewAuthHandler(authRepo, jwtSecret)
	if err != nil {
		return fmt.Errorf("failed to create auth handler: %w", err)
	}

	// 初始化 Gin Router
	router := gin.Default()

	// 設定 CORS (Cross-Origin Resource Sharing)
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	if len(allowedOrigins) == 0 || allowedOrigins[0] == "" {
		return errors.New("ALLOWED_ORIGINS environment variable must be set")
	}
	router.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 設定安全 Headers
	router.Use(middleware.SecurityHeaders())

	// 設定 Host Header 驗證（防止 SSRF 攻擊）
	backendDomain := os.Getenv("BACKEND_DOMAIN")
	if backendDomain == "" {
		return errBackendDomainNotSet
	}
	router.Use(middleware.HostHeaderValidation(backendDomain))

	handler.RegisterRoutes(router)
	authHandler.RegisterRoutes(router)

	// 健康檢查路由
	router.GET("/healthz", func(c *gin.Context) {
		if err := dbpool.Ping(c); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Database connection is down"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "Database connection is healthy"})
	})

	backendPort := os.Getenv("BACKEND_PORT")
	if backendPort == "" {
		backendPort = "8080"
	}

	log.Printf("Starting server on :%s", backendPort)
	if err := router.Run(":" + backendPort); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

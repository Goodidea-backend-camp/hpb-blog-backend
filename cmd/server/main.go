package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/api"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errDatabaseURLNotSet = errors.New("DATABASE_URL environment variable is not set")

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
	authStore := store.NewAuthStore(queries)

	// 初始化 Handler
	handler := api.NewHandler(postStore)

	// 從 .env 取得 JWT secret
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return errors.New("JWT_SECRET environment variable is not set")
	}

	// 初始化 AuthHandler
	authHandler, err := api.NewAuthHandler(authStore, jwtSecret)
	if err != nil {
		return fmt.Errorf("failed to create auth handler: %w", err)
	}

	// 初始化 Gin Router
	router := gin.Default()
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

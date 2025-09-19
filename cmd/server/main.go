package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/api"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	databaseUrl := os.Getenv("DATABASE_URL")
	if databaseUrl == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	dbpool, err := pgxpool.New(context.Background(), databaseUrl)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}
	defer dbpool.Close()

	if err := dbpool.Ping(context.Background()); err != nil {
		log.Fatalf("Unable to ping database: %v\n", err)
	}

	log.Println("Successfully connected to the database!")

	// 初始化 DB Queries 和 Store
	queries := db.New(dbpool)
	postStore := store.NewPostStore(queries)

	// 初始化 Handler
	handler := api.NewHandler(postStore)

	// 初始化 Gin Router
	router := gin.Default()
	handler.RegisterRoutes(router)

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
		log.Fatal(err)
	}
}

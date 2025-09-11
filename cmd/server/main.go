package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// 從環境變數讀取資料庫連線字串
	databaseUrl := os.Getenv("DATABASE_URL")
	if databaseUrl == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	// 建立資料庫連線池
	dbpool, err := pgxpool.New(context.Background(), databaseUrl)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}
	// 在 main 函式結束時關閉連線池
	defer dbpool.Close()

	// Ping 資料庫以驗證連線
	if err := dbpool.Ping(context.Background()); err != nil {
		log.Fatalf("Unable to ping database: %v\n", err)
	}

	log.Println("Successfully connected to the database!")

	// 主頁路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World from Golang Backend!")
	})

	// 健康檢查路由
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := dbpool.Ping(r.Context()); err != nil {
			http.Error(w, "Database connection is down", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Database connection is healthy")
	})

	// 從環境變數讀取後端服務要監聽的 port
	backendPort := os.Getenv("BACKEND_PORT")
	if backendPort == "" {
		backendPort = "8080" // 如果沒有設定，預設為 8080
	}

	listenAddr := fmt.Sprintf(":%s", backendPort)
	log.Printf("Starting server on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}

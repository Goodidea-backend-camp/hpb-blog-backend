// Package database 提供資料庫連線的共用功能
package database

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrDatabaseURLNotSet 表示 DATABASE_URL 環境變數未設定
var ErrDatabaseURLNotSet = errors.New("DATABASE_URL environment variable is not set")

// NewPool 建立並驗證資料庫連線池
// 此函數會：
// 1. 從環境變數讀取 DATABASE_URL
// 2. 建立連線池
// 3. 執行 ping 驗證連線
//
// 如果任何步驟失敗，會回傳錯誤
// 呼叫方需要負責在使用完畢後呼叫 pool.Close()
func NewPool(ctx context.Context) (*pgxpool.Pool, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, ErrDatabaseURLNotSet
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/cmd/artisan/commands"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/pkg/database"
)

func run() error {
	if len(os.Args) < 2 {
		printHelp()
		return nil
	}

	// 初始化資料庫連線
	dbpool, err := database.NewPool(context.Background())
	if err != nil {
		return err
	}
	defer dbpool.Close()

	// 初始化 Queries 和 Stores
	queries := db.New(dbpool)
	userStore := store.NewUserStore(queries)

	// 路由命令
	ctx := context.Background()
	command := os.Args[1]

	switch command {
	case "make:user":
		return commands.MakeUser(ctx, userStore)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printHelp()
		return nil
	}
}

func printHelp() {
	fmt.Println("If you in Container Usage: go run cmd/artisan/main.go [command]")
	fmt.Println("If you in Local Usage: make artisan [command]")
	fmt.Println("Now Available commands:")
	fmt.Println("  make:user    Create a new user")
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

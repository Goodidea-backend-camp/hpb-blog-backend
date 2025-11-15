package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// TestUser represents a test user to be seeded into the database.
type TestUser struct {
	Username string
	Password string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Define test users to seed
	testUsers := []TestUser{
		{Username: "test", Password: "test"},
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database not responding: %w", err)
	}

	fmt.Println("Seeding database...")

	// Seed each test user
	for _, user := range testUsers {
		if err := seedUser(ctx, pool, user); err != nil {
			fmt.Printf("ERROR: %s: %v\n", user.Username, err)
		} else {
			fmt.Printf("SUCCESS: %s\n", user.Username)
		}
	}

	fmt.Println("Seed completed")
	return nil
}

func seedUser(ctx context.Context, pool *pgxpool.Pool, user TestUser) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash generation failed: %w", err)
	}

	query := `
		INSERT INTO users (username, password, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (username) DO UPDATE
			SET password = EXCLUDED.password,
			    updated_at = NOW()
	`

	_, err = pool.Exec(ctx, query, user.Username, string(hash))
	if err != nil {
		return fmt.Errorf("database insert failed: %w", err)
	}

	return nil
}

package main

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestUser 定義測試用戶結構
type TestUser struct {
	Username     string
	Password     string // 明文密碼
	PasswordHash string // bcrypt 加密後的密碼
}

// GenerateTestUser 生成測試用戶
func GenerateTestUser(username, password string) (*TestUser, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	return &TestUser{
		Username:     username,
		Password:     password,
		PasswordHash: string(hash),
	}, nil
}

func main() {
	// 預設測試用戶
	testUsers := []struct {
		username string
		password string
	}{
		{"test", "test"},
	}

	fmt.Println("=== HPB Blog Test User Factory ===")
	fmt.Println("Generated at:", time.Now().Format(time.RFC3339))
	fmt.Println()

	for i, user := range testUsers {
		testUser, err := GenerateTestUser(user.username, user.password)
		if err != nil {
			log.Fatalf("Error generating user %s: %v", user.username, err)
		}

		fmt.Printf("--- Test User #%d ---\n", i+1)
		fmt.Printf("Username: %s\n", testUser.Username)
		fmt.Printf("Password (plaintext): %s\n", testUser.Password)
		fmt.Printf("Password (bcrypt): %s\n", testUser.PasswordHash)
		fmt.Println()

		// SQL 插入語句
		fmt.Println("SQL Insert Statement:")
		fmt.Printf("INSERT INTO users (username, password, created_at, updated_at) VALUES ('%s', '%s', NOW(), NOW());\n", testUser.Username, testUser.PasswordHash)
		fmt.Println()
		fmt.Println("---")
		fmt.Println()
	}

	fmt.Println("=== Usage Instructions ===")
	fmt.Println("1. Run: make factory")
	fmt.Println("2. Copy the SQL INSERT statement above")
	fmt.Println("3. Connect to database:")
	fmt.Println("   docker exec -it <db_container> psql -U hpb_user -d hpb_blog_db")
	fmt.Println("4. Paste the SQL statement to insert test user")
	fmt.Println()
	fmt.Println("Or use the quick command:")
	fmt.Println("   make factory-seed")
}

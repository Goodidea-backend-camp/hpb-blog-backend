package commands

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// MakeUser 互動式創建使用者
func MakeUser(ctx context.Context, userStore store.UserStore) error {
	reader := bufio.NewReader(os.Stdin)

	// 1. 輸入 username
	fmt.Print("Enter username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}
	username = strings.TrimSpace(username)

	// 驗證 username
	if username == "" {
		return errors.New("username cannot be empty")
	}
	if len(username) < 3 {
		return errors.New("username must be at least 3 characters")
	}

	// 檢查 username 是否已存在
	_, err = userStore.GetUserByUsername(ctx, username)
	if err == nil {
		return fmt.Errorf("username '%s' already exists", username)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to check username: %w", err)
	}

	// 2. 輸入 password（隱藏輸入）
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	password := string(passwordBytes)

	// 驗證 password
	if password == "" {
		return errors.New("password cannot be empty")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	// 3. 確認 password
	fmt.Print("Confirm password: ")
	confirmPasswordBytes, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}
	fmt.Println()

	confirmPassword := string(confirmPasswordBytes)

	if password != confirmPassword {
		return errors.New("passwords do not match")
	}

	// 4. 加密密碼
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// 5. 創建使用者
	user, err := userStore.CreateUser(ctx, db.CreateUserParams{
		Username: username,
		Password: string(hashedPassword),
	})
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// 6. 顯示成功訊息
	fmt.Println("\nUser created successfully!")
	fmt.Printf("   ID: %d\n", user.ID)
	fmt.Printf("   Username: %s\n", user.Username)
	fmt.Printf("   Created at: %v\n", user.CreatedAt.Time)

	return nil
}

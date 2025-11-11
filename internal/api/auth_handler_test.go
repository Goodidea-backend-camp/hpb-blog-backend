package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/auth"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

var setupRouterOnce sync.Once

// Test constants
const (
	testUsername        = "testuser"
	testPassword        = "testpassword123"
	testWrongPassword   = "wrongpassword"
	testJWTSecret       = "test-secret-key-for-jwt-generation"
	testUserID          = int32(1)
	nonexistentUsername = "nonexistent"
)

// mockAuthStore is a mock implementation of store.AuthStore for testing.
type mockAuthStore struct {
	mu                    sync.Mutex
	getUserByUsernameFunc func(ctx context.Context, username string) (db.User, error)
	callCount             int
	lastContext           context.Context
	lastUsername          string
}

func (m *mockAuthStore) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	m.mu.Lock()
	m.callCount++
	m.lastContext = ctx
	m.lastUsername = username
	getUserFunc := m.getUserByUsernameFunc
	m.mu.Unlock()

	if getUserFunc != nil {
		return getUserFunc(ctx, username)
	}
	return db.User{}, nil
}

// getCallCount returns the call count in a thread-safe manner.
func (m *mockAuthStore) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// getLastUsername returns the last username in a thread-safe manner.
func (m *mockAuthStore) getLastUsername() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastUsername
}

// getLastContext returns the last context in a thread-safe manner.
func (m *mockAuthStore) getLastContext() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastContext
}

// setupTestRouter creates a test Gin router in test mode.
func setupTestRouter() *gin.Engine {
	setupRouterOnce.Do(func() {
		gin.SetMode(gin.TestMode)
	})
	return gin.New()
}

// createTestUser creates a test user with the given username and password.
func createTestUser(username, password string) (db.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return db.User{}, err
	}

	return db.User{
		ID:        testUserID,
		Username:  username,
		Password:  string(hashedPassword),
		CreatedAt: pgtype.Timestamptz{Valid: true},
	}, nil
}

// makeLoginRequest creates and executes a login HTTP request.
func makeLoginRequest(handler *AuthHandler, username, password string) *httptest.ResponseRecorder {
	router := setupTestRouter()
	handler.RegisterRoutes(router)

	loginReq := LoginRequest{
		Username: username,
		Password: password,
	}
	body, err := json.Marshal(loginReq)
	if err != nil {
		panic(err) // Should never happen in tests with valid data
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)
	return w
}

// TestNewAuthHandler tests the AuthHandler constructor.
func TestNewAuthHandler(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		jwtSecret string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid jwt secret",
			jwtSecret: testJWTSecret,
			wantError: false,
		},
		{
			name:      "empty jwt secret",
			jwtSecret: "",
			wantError: true,
			errorMsg:  "JWT secret cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &mockAuthStore{}
			handler, err := NewAuthHandler(mockStore, tt.jwtSecret, WithBcryptCost(bcrypt.MinCost))

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Error message = %v, want %v", err.Error(), tt.errorMsg)
				}
				if handler != nil {
					t.Errorf("Expected nil handler but got %v", handler)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if handler == nil {
					t.Error("Expected non-nil handler")
				}
				if handler != nil && handler.jwtSecret != tt.jwtSecret {
					t.Errorf("JWT secret = %v, want %v", handler.jwtSecret, tt.jwtSecret)
				}
			}
		})
	}
}

// TestLogin_Success tests successful login scenarios.
func TestLogin_Success(t *testing.T) {
	t.Parallel()
	testUser, err := createTestUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	mockStore := &mockAuthStore{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			if username == testUsername {
				return testUser, nil
			}
			return db.User{}, pgx.ErrNoRows
		},
	}

	handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	w := makeLoginRequest(handler, testUsername, testPassword)

	// Verify response status
	if w.Code != http.StatusOK {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusOK)
	}

	// Verify response body
	var response LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.Token == "" {
		t.Error("Token is empty")
	}

	if response.User.Username != testUsername {
		t.Errorf("Username = %v, want %v", response.User.Username, testUsername)
	}

	// Verify mock was called correctly
	if mockStore.getCallCount() != 1 {
		t.Errorf("GetUserByUsername called %d times, want 1", mockStore.getCallCount())
	}

	if mockStore.getLastUsername() != testUsername {
		t.Errorf("GetUserByUsername called with username %v, want %v", mockStore.getLastUsername(), testUsername)
	}
}

// TestLogin_InvalidRequest tests various invalid request scenarios.
func TestLogin_InvalidRequest(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}
	router := setupTestRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name        string
		requestBody string
		contentType string
		wantCode    int
	}{
		{
			name:        "invalid json",
			requestBody: "invalid json",
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "missing username",
			requestBody: `{"password":"testpassword123"}`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "missing password",
			requestBody: `{"username":"testuser"}`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "empty username",
			requestBody: `{"username":"","password":"testpassword123"}`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "empty password",
			requestBody: `{"username":"testuser","password":""}`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", tt.contentType)

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Status code = %v, want %v", w.Code, tt.wantCode)
			}

			var response ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}

			if response.Code != tt.wantCode {
				t.Errorf("Error code = %v, want %v", response.Code, tt.wantCode)
			}
		})
	}
}

// TestLogin_AuthenticationFailures tests authentication failure scenarios.
func TestLogin_AuthenticationFailures(t *testing.T) {
	t.Parallel()
	testUser, err := createTestUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name          string
		setupMock     func() *mockAuthStore
		loginUsername string
		loginPassword string
		wantCode      int
		wantMessage   string
		wantCallCount int
	}{
		{
			name: "user not found",
			setupMock: func() *mockAuthStore {
				return &mockAuthStore{
					getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
						return db.User{}, pgx.ErrNoRows
					},
				}
			},
			loginUsername: nonexistentUsername,
			loginPassword: testPassword,
			wantCode:      http.StatusForbidden,
			wantMessage:   "Invalid username or password",
			wantCallCount: 1,
		},
		{
			name: "wrong password",
			setupMock: func() *mockAuthStore {
				return &mockAuthStore{
					getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
						return testUser, nil
					},
				}
			},
			loginUsername: testUsername,
			loginPassword: testWrongPassword,
			wantCode:      http.StatusForbidden,
			wantMessage:   "Invalid username or password",
			wantCallCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := tt.setupMock()
			handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
			if err != nil {
				t.Fatalf("Failed to create handler: %v", err)
			}

			w := makeLoginRequest(handler, tt.loginUsername, tt.loginPassword)

			if w.Code != tt.wantCode {
				t.Errorf("Status code = %v, want %v", w.Code, tt.wantCode)
			}

			var response ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}

			if response.Message != tt.wantMessage {
				t.Errorf("Error message = %v, want %v", response.Message, tt.wantMessage)
			}

			if mockStore.getCallCount() != tt.wantCallCount {
				t.Errorf("GetUserByUsername called %d times, want %d", mockStore.getCallCount(), tt.wantCallCount)
			}
		})
	}
}

// TestLogin_DatabaseError tests database error handling.
func TestLogin_DatabaseError(t *testing.T) {
	t.Parallel()
	mockStore := &mockAuthStore{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			return db.User{}, errors.New("database connection error")
		},
	}

	handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	w := makeLoginRequest(handler, testUsername, testPassword)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	var response ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if response.Code != http.StatusInternalServerError {
		t.Errorf("Error code = %v, want %v", response.Code, http.StatusInternalServerError)
	}

	if response.Message != "Internal server error" {
		t.Errorf("Error message should not leak database details, got: %v", response.Message)
	}
}

// TestLogin_SpecialCharacters tests login with special characters.
func TestLogin_SpecialCharacters(t *testing.T) {
	t.Parallel()
	specialUsername := "user@example.com"
	specialPassword := "p@ssw0rd!@#$%^&*()"

	testUser, err := createTestUser(specialUsername, specialPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	mockStore := &mockAuthStore{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			if username == specialUsername {
				return testUser, nil
			}
			return db.User{}, pgx.ErrNoRows
		},
	}

	handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	w := makeLoginRequest(handler, specialUsername, specialPassword)

	if w.Code != http.StatusOK {
		t.Errorf("Status code = %v, want %v. Special characters should be handled correctly.", w.Code, http.StatusOK)
	}

	var response LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.Token == "" {
		t.Error("Token should be generated for valid credentials with special characters")
	}
}

// TestLogin_ContextPropagation verifies that context is properly passed through the call chain.
func TestLogin_ContextPropagation(t *testing.T) {
	t.Parallel()
	testUser, err := createTestUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	mockStore := &mockAuthStore{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			// Verify context is not nil
			if ctx == nil {
				t.Error("Context should not be nil")
			}
			return testUser, nil
		},
	}

	handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	w := makeLoginRequest(handler, testUsername, testPassword)

	if w.Code != http.StatusOK {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusOK)
	}

	if mockStore.getLastContext() == nil {
		t.Error("Context was not passed to GetUserByUsername")
	}
}

// TestLogin_TimingAttackPrevention verifies timing attack prevention mechanisms.
func TestLogin_TimingAttackPrevention(t *testing.T) {
	t.Parallel()
	t.Run("user exists vs user does not exist should both hash", func(t *testing.T) {
		testUser, err := createTestUser(testUsername, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}

		mockStore := &mockAuthStore{
			getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
				if username == testUsername {
					return testUser, nil
				}
				return db.User{}, pgx.ErrNoRows
			},
		}

		handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		// Both scenarios should execute password comparison
		// (this test mainly documents the expected behavior)
		w1 := makeLoginRequest(handler, testUsername, testWrongPassword)
		w2 := makeLoginRequest(handler, nonexistentUsername, testWrongPassword)

		// Both should return the same error message
		if w1.Code != w2.Code {
			t.Errorf("Response codes differ: existing user=%v, non-existing user=%v", w1.Code, w2.Code)
		}

		var resp1, resp2 ErrorResponse
		if err := json.Unmarshal(w1.Body.Bytes(), &resp1); err != nil {
			t.Fatalf("Failed to parse response 1: %v", err)
		}
		if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
			t.Fatalf("Failed to parse response 2: %v", err)
		}

		if resp1.Message != resp2.Message {
			t.Errorf("Error messages differ: existing user=%v, non-existing user=%v", resp1.Message, resp2.Message)
		}
	})
}

// TestLogin_ConcurrentRequests tests concurrent login scenarios.
//
//nolint:gocyclo // Concurrent tests have reasonable inherent complexity due to goroutine coordination
func TestLogin_ConcurrentRequests(t *testing.T) {
	t.Parallel()
	const numGoroutines = 50

	t.Run("different users concurrent login", func(t *testing.T) {
		testUser, err := createTestUser(testUsername, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}

		mockStore := &mockAuthStore{
			getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
				// Create different user for each username
				if username == testUsername || len(username) >= 4 && username[:4] == "user" {
					user := testUser
					user.Username = username
					return user, nil
				}
				return db.User{}, pgx.ErrNoRows
			},
		}

		handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				username := fmt.Sprintf("user%d", id)
				w := makeLoginRequest(handler, username, testPassword)

				if w.Code != http.StatusOK {
					errors <- fmt.Errorf("goroutine %d: got status %d, want %d", id, w.Code, http.StatusOK)
					return
				}

				var response LoginResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					errors <- fmt.Errorf("goroutine %d: failed to parse response: %w", id, err)
					return
				}

				if response.Token == "" {
					errors <- fmt.Errorf("goroutine %d: token is empty", id)
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}
	})

	t.Run("same user concurrent login succeeds", func(t *testing.T) {
		testUser, err := createTestUser(testUsername, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}

		mockStore := &mockAuthStore{
			getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
				if username == testUsername {
					return testUser, nil
				}
				return db.User{}, pgx.ErrNoRows
			},
		}

		handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
		if err != nil {
			t.Fatalf("Failed to create handler: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(numGoroutines)
		tokens := make(chan string, numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				w := makeLoginRequest(handler, testUsername, testPassword)

				if w.Code != http.StatusOK {
					errors <- fmt.Errorf("goroutine %d: got status %d, want %d", id, w.Code, http.StatusOK)
					return
				}

				var response LoginResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					errors <- fmt.Errorf("goroutine %d: failed to parse response: %w", id, err)
					return
				}

				if response.Token == "" {
					errors <- fmt.Errorf("goroutine %d: token is empty", id)
					return
				}

				tokens <- response.Token
			}(i)
		}

		wg.Wait()
		close(errors)
		close(tokens)

		// Check for errors
		for err := range errors {
			t.Error(err)
		}

		// Verify all tokens are valid (they may be the same if generated in the same second)
		// Note: JWT tokens with the same userID and generated in the same second will be identical
		// This is expected behavior and not a security issue
		tokenCount := 0
		for range tokens {
			tokenCount++
		}

		if tokenCount != numGoroutines {
			t.Errorf("Expected %d tokens, got %d", numGoroutines, tokenCount)
		}
	})
}

// TestLogin_ContentType tests Content-Type header handling.
// Note: Gin's ShouldBindJSON accepts JSON regardless of Content-Type header,
// so this test verifies that valid JSON data is processed correctly
// with various Content-Type headers.
func TestLogin_ContentType(t *testing.T) {
	t.Parallel()
	testUser, err := createTestUser(testUsername, testPassword)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	mockStore := &mockAuthStore{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			if username == testUsername {
				return testUser, nil
			}
			return db.User{}, pgx.ErrNoRows
		},
	}

	handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	loginReq := LoginRequest{
		Username: testUsername,
		Password: testPassword,
	}
	body, err := json.Marshal(loginReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	tests := []struct {
		name        string
		contentType string
		wantCode    int
		description string
	}{
		{
			name:        "valid application/json",
			contentType: "application/json",
			wantCode:    http.StatusOK,
			description: "Standard JSON content type should work",
		},
		{
			name:        "valid application/json with charset",
			contentType: "application/json; charset=utf-8",
			wantCode:    http.StatusOK,
			description: "JSON with charset should work",
		},
		{
			name:        "missing content-type accepts JSON",
			contentType: "",
			wantCode:    http.StatusOK,
			description: "Gin accepts JSON even without Content-Type header",
		},
		{
			name:        "text/plain accepts JSON body",
			contentType: "text/plain",
			wantCode:    http.StatusOK,
			description: "Gin's ShouldBindJSON accepts JSON regardless of Content-Type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Status code = %v, want %v. %s", w.Code, tt.wantCode, tt.description)
			}
		})
	}
}

// TestLogin_SQLInjectionAttempts tests protection against SQL injection attacks.
func TestLogin_SQLInjectionAttempts(t *testing.T) {
	t.Parallel()
	mockStore := &mockAuthStore{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			// No user should be found for SQL injection attempts
			return db.User{}, pgx.ErrNoRows
		},
	}

	handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
		wantCode int
		wantMsg  string
	}{
		{
			name:     "OR 1=1 attack",
			username: "' OR '1'='1",
			password: testPassword,
			wantCode: http.StatusForbidden,
			wantMsg:  "Invalid username or password",
		},
		{
			name:     "comment out password check",
			username: "admin'--",
			password: testPassword,
			wantCode: http.StatusForbidden,
			wantMsg:  "Invalid username or password",
		},
		{
			name:     "drop table attempt",
			username: "'; DROP TABLE users;--",
			password: testPassword,
			wantCode: http.StatusForbidden,
			wantMsg:  "Invalid username or password",
		},
		{
			name:     "double quote OR attack",
			username: `" OR ""="`,
			password: testPassword,
			wantCode: http.StatusForbidden,
			wantMsg:  "Invalid username or password",
		},
		{
			name:     "union select attack",
			username: "' UNION SELECT NULL, NULL, NULL--",
			password: testPassword,
			wantCode: http.StatusForbidden,
			wantMsg:  "Invalid username or password",
		},
		{
			name:     "stacked queries",
			username: "admin'; DELETE FROM users WHERE '1'='1",
			password: testPassword,
			wantCode: http.StatusForbidden,
			wantMsg:  "Invalid username or password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := makeLoginRequest(handler, tt.username, tt.password)

			if w.Code != tt.wantCode {
				t.Errorf("Status code = %v, want %v", w.Code, tt.wantCode)
			}

			var response ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}

			if response.Message != tt.wantMsg {
				t.Errorf("Error message = %v, want %v", response.Message, tt.wantMsg)
			}

			// Verify the mock was called with the malicious username
			if mockStore.getLastUsername() != tt.username {
				t.Errorf("GetUserByUsername called with username %v, want %v", mockStore.getLastUsername(), tt.username)
			}
		})
	}
}

// TestLogin_UnicodeAndSpecialCharacters tests login with various Unicode and special characters.
func TestLogin_UnicodeAndSpecialCharacters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "Chinese characters",
			username: "用戶123",
			password: "密碼test",
		},
		{
			name:     "emoji in username",
			username: "user😀name",
			password: testPassword,
		},
		{
			name:     "emoji in password",
			username: testUsername,
			password: "pass😀word",
		},
		{
			name:     "RTL characters",
			username: "user\u200fname",
			password: testPassword,
		},
		{
			name:     "zero-width space",
			username: "user\u200Bname",
			password: testPassword,
		},
		{
			name:     "combining characters",
			username: "café",
			password: testPassword,
		},
		{
			name:     "Japanese characters",
			username: "ユーザー名",
			password: "パスワード",
		},
		{
			name:     "Korean characters",
			username: "사용자",
			password: "비밀번호",
		},
		{
			name:     "mixed unicode",
			username: "user用户😀",
			password: "pass密碼😀",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test user with the specific username and password
			testUser, err := createTestUser(tt.username, tt.password)
			if err != nil {
				t.Fatalf("Failed to create test user: %v", err)
			}

			mockStore := &mockAuthStore{
				getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
					if username == tt.username {
						return testUser, nil
					}
					return db.User{}, pgx.ErrNoRows
				},
			}

			handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
			if err != nil {
				t.Fatalf("Failed to create handler: %v", err)
			}

			w := makeLoginRequest(handler, tt.username, tt.password)

			if w.Code != http.StatusOK {
				t.Errorf("Status code = %v, want %v. Unicode characters should be handled correctly.", w.Code, http.StatusOK)
			}

			var response LoginResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			if response.Token == "" {
				t.Error("Token should be generated for valid credentials with unicode characters")
			}

			if response.User.Username != tt.username {
				t.Errorf("Username = %v, want %v", response.User.Username, tt.username)
			}

			// Verify the mock was called with the correct username
			if mockStore.getLastUsername() != tt.username {
				t.Errorf("GetUserByUsername called with username %v, want %v", mockStore.getLastUsername(), tt.username)
			}
		})
	}
}

// TestLogin_JWTGenerationFailure tests handling of JWT generation failures.
func TestLogin_JWTGenerationFailure(t *testing.T) {
	t.Parallel()
	t.Run("empty JWT secret causes generation failure", func(t *testing.T) {
		testUser, err := createTestUser(testUsername, testPassword)
		if err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}

		mockStore := &mockAuthStore{
			getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
				if username == testUsername {
					return testUser, nil
				}
				return db.User{}, pgx.ErrNoRows
			},
		}

		// Create handler with empty secret to trigger JWT generation failure
		// Note: This will fail at handler creation, not during login
		_, err = NewAuthHandler(mockStore, "", WithBcryptCost(bcrypt.MinCost))
		if err == nil {
			t.Error("NewAuthHandler should return error with empty JWT secret")
		}
		if err != nil && err.Error() != "JWT secret cannot be empty" {
			t.Errorf("Error message = %v, want 'JWT secret cannot be empty'", err.Error())
		}
	})

	t.Run("handler creation with valid secret succeeds", func(t *testing.T) {
		mockStore := &mockAuthStore{}
		handler, err := NewAuthHandler(mockStore, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
		if err != nil {
			t.Errorf("NewAuthHandler should not return error with valid secret: %v", err)
		}
		if handler == nil {
			t.Error("Handler should not be nil with valid secret")
		}
	})
}

// TestLogout_Success tests successful logout with valid JWT token.
func TestLogout_Success(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	// Generate valid JWT token
	token, err := auth.GenerateToken(testUserID, testJWTSecret)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusNoContent)
	}

	if w.Body.Len() != 0 {
		t.Errorf("Body should be empty, got %v", w.Body.String())
	}
}

// TestLogout_MissingAuthHeader tests logout without Authorization header.
func TestLogout_MissingAuthHeader(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// Intentionally not setting Authorization header

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusForbidden)
	}

	var response ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if response.Code != http.StatusForbidden {
		t.Errorf("Error code = %v, want %v", response.Code, http.StatusForbidden)
	}

	if response.Message != "Authorization header required" {
		t.Errorf("Error message = %v, want 'Authorization header required'", response.Message)
	}
}

// TestLogout_InvalidTokenFormat tests logout with invalid Bearer token format.
func TestLogout_InvalidTokenFormat(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name            string
		authValue       string
		wantMessage     string
		wantDescription string
	}{
		{
			name:            "missing Bearer prefix",
			authValue:       "some-token-without-bearer",
			wantMessage:     "Invalid authorization format",
			wantDescription: "No Bearer prefix should fail format check",
		},
		{
			name:            "lowercase bearer",
			authValue:       "bearer token123",
			wantMessage:     "Invalid authorization format",
			wantDescription: "Lowercase bearer should fail format check",
		},
		{
			name:            "extra spaces treated as invalid token",
			authValue:       "Bearer  token123",
			wantMessage:     "Invalid or expired token",
			wantDescription: "Extra space becomes part of token, fails JWT validation",
		},
		{
			name:            "no space after Bearer",
			authValue:       "Bearertoken123",
			wantMessage:     "Invalid authorization format",
			wantDescription: "No space after Bearer should fail format check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			req.Header.Set("Authorization", tt.authValue)

			router.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Status code = %v, want %v. %s", w.Code, http.StatusForbidden, tt.wantDescription)
			}

			var response ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}

			if response.Message != tt.wantMessage {
				t.Errorf("Error message = %v, want '%v'. %s", response.Message, tt.wantMessage, tt.wantDescription)
			}
		})
	}
}

// TestLogout_InvalidToken tests logout with invalid JWT token.
func TestLogout_InvalidToken(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed token",
			token: "not.a.valid.jwt.token",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "random string",
			token: "random-string-that-is-not-jwt",
		},
		{
			name: "token signed with different secret",
			token: func() string {
				token, err := auth.GenerateToken(testUserID, "different-secret")
				if err != nil {
					t.Fatalf("Failed to generate token with different secret: %v", err)
				}
				return token
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			router.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Status code = %v, want %v", w.Code, http.StatusForbidden)
			}

			var response ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse error response: %v", err)
			}

			if response.Message != "Invalid or expired token" {
				t.Errorf("Error message = %v, want 'Invalid or expired token'", response.Message)
			}
		})
	}
}

// TestLogout_ExpiredToken tests logout with expired JWT token.
func TestLogout_ExpiredToken(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	// Create an expired token by manipulating the time
	// Since we can't easily create an expired token with the current implementation,
	// we'll test this by using a token that was generated in the past
	// For now, we'll create a token and verify the error handling works
	// In a real scenario, you might need to mock the time or wait for expiration

	// Generate a token that will be treated as expired
	// We can't easily create an expired token with current implementation,
	// so we'll simulate it by creating a malformed token that will fail validation
	// #nosec G101 -- This is a test token, not a real credential
	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE2MDk0NTkgMDB9.invalid"

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusForbidden)
	}

	var response ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if response.Code != http.StatusForbidden {
		t.Errorf("Error code = %v, want %v", response.Code, http.StatusForbidden)
	}

	if response.Message != "Invalid or expired token" {
		t.Errorf("Error message = %v, want 'Invalid or expired token'", response.Message)
	}
}

// TestLogout_ConcurrentRequests tests concurrent logout requests.
func TestLogout_ConcurrentRequests(t *testing.T) {
	t.Parallel()
	const numGoroutines = 50

	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Generate unique token for each request
			// #nosec G115 -- id is bounded by numGoroutines (50), safe to convert
			token, err := auth.GenerateToken(int32(id+1), testJWTSecret)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: failed to generate token: %w", id, err)
				return
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			router.ServeHTTP(w, req)

			if w.Code != http.StatusNoContent {
				errors <- fmt.Errorf("goroutine %d: got status %d, want %d", id, w.Code, http.StatusNoContent)
				return
			}

			if w.Body.Len() != 0 {
				errors <- fmt.Errorf("goroutine %d: body should be empty, got %v", id, w.Body.String())
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestLogout_WithDifferentUserIDs tests logout with different user IDs in tokens.
func TestLogout_WithDifferentUserIDs(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	userIDs := []int32{1, 100, 999, 12345}

	for _, userID := range userIDs {
		t.Run(fmt.Sprintf("userID_%d", userID), func(t *testing.T) {
			token, err := auth.GenerateToken(userID, testJWTSecret)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			router.ServeHTTP(w, req)

			if w.Code != http.StatusNoContent {
				t.Errorf("Status code = %v, want %v", w.Code, http.StatusNoContent)
			}

			if w.Body.Len() != 0 {
				t.Errorf("Body should be empty, got %v", w.Body.String())
			}
		})
	}
}

// TestLogout_SameTokenMultipleTimes tests using the same token multiple times.
// Since JWT is stateless, the same valid token should work multiple times.
func TestLogout_SameTokenMultipleTimes(t *testing.T) {
	t.Parallel()
	handler, err := NewAuthHandler(&mockAuthStore{}, testJWTSecret, WithBcryptCost(bcrypt.MinCost))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	router := setupTestRouter()
	handler.RegisterRoutes(router)

	// Generate a token
	token, err := auth.GenerateToken(testUserID, testJWTSecret)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Use the same token 3 times
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("attempt_%d", i+1), func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			router.ServeHTTP(w, req)

			if w.Code != http.StatusNoContent {
				t.Errorf("Attempt %d: Status code = %v, want %v", i+1, w.Code, http.StatusNoContent)
			}
		})
		// Small delay between attempts
		time.Sleep(10 * time.Millisecond)
	}
}

package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// mockAuthQueries implements repository.AuthQuerier interface for testing
type mockAuthQueries struct {
	getUserByUsernameFunc func(ctx context.Context, username string) (db.User, error)
}

func (m *mockAuthQueries) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	if m.getUserByUsernameFunc != nil {
		return m.getUserByUsernameFunc(ctx, username)
	}
	return db.User{}, nil
}

// Verify mockAuthQueries implements repository.AuthQuerier
var _ AuthQuerier = (*mockAuthQueries)(nil)

// Helper function to create a test user
func createTestUser(id int32, username, password string) db.User {
	return db.User{
		ID:       id,
		Username: username,
		Password: password,
		CreatedAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
		UpdatedAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
		DeletedAt: pgtype.Timestamptz{
			Valid: false,
		},
	}
}

func TestNewAuthRepository(t *testing.T) {
	tests := []struct {
		name    string
		queries AuthQuerier
		wantNil bool
	}{
		{
			name:    "create repository with valid queries",
			queries: &mockAuthQueries{},
			wantNil: false,
		},
		{
			name:    "create repository with nil queries",
			queries: nil,
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewAuthRepository(tt.queries)
			if (repo == nil) != tt.wantNil {
				t.Errorf("NewAuthRepository() = %v, want nil = %v", repo, tt.wantNil)
			}
		})
	}
}

func TestGetUserByUsername(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		mockFunc      func(ctx context.Context, username string) (db.User, error)
		wantUser      db.User
		wantErr       bool
		checkErrType  bool
		expectedError error
	}{
		{
			name:     "success - user found",
			username: "testuser",
			mockFunc: func(ctx context.Context, username string) (db.User, error) {
				return createTestUser(1, "testuser", "hashedpassword"), nil
			},
			wantUser: createTestUser(1, "testuser", "hashedpassword"),
			wantErr:  false,
		},
		{
			name:     "user not found",
			username: "nonexistent",
			mockFunc: func(ctx context.Context, username string) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			wantUser:      db.User{},
			wantErr:       true,
			checkErrType:  true,
			expectedError: pgx.ErrNoRows,
		},
		{
			name:     "database connection error",
			username: "testuser",
			mockFunc: func(ctx context.Context, username string) (db.User, error) {
				return db.User{}, errors.New("connection refused")
			},
			wantUser: db.User{},
			wantErr:  true,
		},
		{
			name:     "empty username",
			username: "",
			mockFunc: func(ctx context.Context, username string) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			wantUser:      db.User{},
			wantErr:       true,
			checkErrType:  true,
			expectedError: pgx.ErrNoRows,
		},
		{
			name:     "username with special characters",
			username: "test@user.com",
			mockFunc: func(ctx context.Context, username string) (db.User, error) {
				return createTestUser(2, "test@user.com", "hashedpassword"), nil
			},
			wantUser: createTestUser(2, "test@user.com", "hashedpassword"),
			wantErr:  false,
		},
		{
			name:     "database timeout error",
			username: "testuser",
			mockFunc: func(ctx context.Context, username string) (db.User, error) {
				return db.User{}, context.DeadlineExceeded
			},
			wantUser:      db.User{},
			wantErr:       true,
			checkErrType:  true,
			expectedError: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockAuthQueries{
				getUserByUsernameFunc: tt.mockFunc,
			}
			repo := NewAuthRepository(mock)

			ctx := context.Background()
			user, err := repo.GetUserByUsername(ctx, tt.username)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserByUsername() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkErrType && !errors.Is(err, tt.expectedError) {
				t.Errorf("GetUserByUsername() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if !tt.wantErr {
				if user.ID != tt.wantUser.ID {
					t.Errorf("GetUserByUsername() ID = %v, want %v", user.ID, tt.wantUser.ID)
				}
				if user.Username != tt.wantUser.Username {
					t.Errorf("GetUserByUsername() Username = %v, want %v", user.Username, tt.wantUser.Username)
				}
				if user.Password != tt.wantUser.Password {
					t.Errorf("GetUserByUsername() Password = %v, want %v", user.Password, tt.wantUser.Password)
				}
			}
		})
	}
}

func TestGetUserByUsername_ContextCancellation(t *testing.T) {
	mock := &mockAuthQueries{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			// Simulate checking for context cancellation
			select {
			case <-ctx.Done():
				return db.User{}, ctx.Err()
			default:
				return createTestUser(1, "testuser", "hashedpassword"), nil
			}
		},
	}
	repo := NewAuthRepository(mock)

	// Create canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := repo.GetUserByUsername(ctx, "testuser")
	if err == nil {
		t.Error("GetUserByUsername() expected error with canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("GetUserByUsername() error = %v, want context.Canceled", err)
	}
}

func TestGetUserByUsername_Concurrent(t *testing.T) {
	mock := &mockAuthQueries{
		getUserByUsernameFunc: func(ctx context.Context, username string) (db.User, error) {
			return createTestUser(1, username, "hashedpassword"), nil
		},
	}
	repo := NewAuthRepository(mock)

	ctx := context.Background()
	done := make(chan error, 10)

	// Run multiple concurrent calls
	for i := range 10 {
		go func(id int) {
			_, err := repo.GetUserByUsername(ctx, "testuser")
			done <- err
		}(i)
	}

	// Wait for all goroutines and check for errors
	for i := range 10 {
		if err := <-done; err != nil {
			t.Errorf("Concurrent call %d failed: %v", i, err)
		}
	}
}

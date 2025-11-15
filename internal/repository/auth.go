package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
	"github.com/jackc/pgx/v5"
)

// Domain errors for auth repository
var (
	ErrUserNotFound  = errors.New("user not found")
	ErrDatabaseQuery = errors.New("database query failed")
	ErrDatabaseConn  = errors.New("database connection failed")
	ErrTimeout       = errors.New("operation timeout")
	ErrCanceled      = errors.New("operation canceled")
)

// AuthQuerier defines the database operations needed by AuthRepository
type AuthQuerier interface {
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
}

// AuthRepository defines the authentication repository interface
type AuthRepository interface {
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
}

// authRepository is the concrete implementation of AuthRepository
type authRepository struct {
	queries AuthQuerier
}

// NewAuthRepository creates a new AuthRepository instance
func NewAuthRepository(queries AuthQuerier) AuthRepository {
	return &authRepository{
		queries: queries,
	}
}

// GetUserByUsername retrieves a user by username from the database
func (r *authRepository) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	user, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		// Handle context errors
		if errors.Is(err, context.Canceled) {
			return db.User{}, ErrCanceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return db.User{}, ErrTimeout
		}

		// Handle database-specific errors
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}

		// Wrap other database errors
		return db.User{}, fmt.Errorf("%w: %w", ErrDatabaseQuery, err)
	}
	return user, nil
}

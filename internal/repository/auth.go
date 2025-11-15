package repository

import (
	"context"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
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
	return r.queries.GetUserByUsername(ctx, username)
}

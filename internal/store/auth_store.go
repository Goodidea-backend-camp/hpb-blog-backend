package store

import (
	"context"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
)

// AuthQuerier defines the database operations needed by AuthStore
type AuthQuerier interface {
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
}

// AuthStore defines the authentication store interface
type AuthStore interface {
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
}

// authStore is the concrete implementation of AuthStore
type authStore struct {
	queries AuthQuerier
}

// NewAuthStore creates a new AuthStore instance
func NewAuthStore(queries AuthQuerier) AuthStore {
	return &authStore{
		queries: queries,
	}
}

// GetUserByUsername retrieves a user by username from the database
func (s *authStore) GetUserByUsername(ctx context.Context, username string) (db.User, error) {
	return s.queries.GetUserByUsername(ctx, username)
}

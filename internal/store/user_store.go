package store

import (
	"context"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
)

type UserStore interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUser(ctx context.Context, id int32) (db.User, error)
	GetUserByUsername(ctx context.Context, username string) (db.User, error)
	ListUsers(ctx context.Context) ([]db.User, error)
	UpdateUser(ctx context.Context, arg db.UpdateUserParams) (db.User, error)
	DeleteUser(ctx context.Context, id int32) error
}

type SQLUserStore struct {
	*db.Queries
}

func NewUserStore(db *db.Queries) UserStore {
	return &SQLUserStore{
		Queries: db,
	}
}

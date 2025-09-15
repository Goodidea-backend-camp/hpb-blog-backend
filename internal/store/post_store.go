package store

import (
	"context"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/db"
)

type PostStore interface {
	CreatePost(ctx context.Context, arg db.CreatePostParams) (db.Post, error)
	GetPost(ctx context.Context, id int64) (db.Post, error)
	ListPosts(ctx context.Context) ([]db.Post, error)
	UpdatePost(ctx context.Context, arg db.UpdatePostParams) (db.Post, error)
	DeletePost(ctx context.Context, id int64) error
}

type SQLPostStore struct {
	*db.Queries
}

func NewPostStore(db *db.Queries) PostStore {
	return &SQLPostStore{
		Queries: db,
	}
}

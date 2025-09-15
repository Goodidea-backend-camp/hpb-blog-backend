package api

import (
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	store.PostStore
}

func NewHandler(postStore store.PostStore) *Handler {
	return &Handler{
		PostStore: postStore,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	router.POST("/posts", h.CreatePost)
	router.GET("/posts/:id", h.GetPost)
	router.GET("/posts", h.ListPosts)
	router.PUT("/posts/:id", h.UpdatePost)
	router.DELETE("/posts/:id", h.DeletePost)
}

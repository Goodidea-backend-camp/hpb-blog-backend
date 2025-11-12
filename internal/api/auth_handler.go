package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/auth"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/middleware"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	// loginTimeout is the maximum duration for database operations during login.
	loginTimeout = 5 * time.Second
)

// AuthHandler handles authentication-related HTTP requests.
type AuthHandler struct {
	authStore store.AuthStore
	jwtSecret string
	// dummyPasswordHash is used to prevent timing attacks.
	// When a user doesn't exist, we compare against this hash to ensure
	// consistent execution time with real authentication.
	dummyPasswordHash string
}

// AuthHandlerOption is a function that configures an AuthHandler.
type AuthHandlerOption func(*authHandlerConfig)

// authHandlerConfig holds configuration for creating an AuthHandler.
type authHandlerConfig struct {
	bcryptCost int
}

// WithBcryptCost sets a custom bcrypt cost for the AuthHandler.
// This is primarily used for testing to speed up tests by using bcrypt.MinCost.
func WithBcryptCost(cost int) AuthHandlerOption {
	return func(cfg *authHandlerConfig) {
		cfg.bcryptCost = cost
	}
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(authStore store.AuthStore, jwtSecret string, opts ...AuthHandlerOption) (*AuthHandler, error) {
	if jwtSecret == "" {
		return nil, errors.New("JWT secret cannot be empty")
	}

	// Apply default configuration
	cfg := &authHandlerConfig{
		bcryptCost: bcrypt.DefaultCost,
	}

	// Apply provided options
	for _, opt := range opts {
		opt(cfg)
	}

	// Pre-compute dummy hash for timing-attack prevention
	hash, err := bcrypt.GenerateFromPassword(
		[]byte("constant-dummy-password-for-timing-safety"),
		cfg.bcryptCost,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy password hash: %w", err)
	}

	return &AuthHandler{
		authStore:         authStore,
		jwtSecret:         jwtSecret,
		dummyPasswordHash: string(hash),
	}, nil
}

// RegisterRoutes registers authentication routes to the router.
// The logout endpoint is protected by the auth middleware to ensure only
// authenticated users can logout.
func (h *AuthHandler) RegisterRoutes(router *gin.Engine) {
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", h.Login)
		// Protect logout endpoint with auth middleware
		authGroup.POST("/logout", middleware.AuthMiddleware(h.jwtSecret), h.Logout)
	}
}

// LoginRequest represents the login request payload.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginUser represents user information in the login response.
type LoginUser struct {
	Username string `json:"username"`
}

// LoginResponse represents a successful login response.
type LoginResponse struct {
	Token string    `json:"token"`
	User  LoginUser `json:"user"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Login handles user authentication.
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid request format",
		})
		return
	}

	var userExists bool
	var passwordHash string

	// Set timeout for database query to prevent indefinite blocking
	ctx, cancel := context.WithTimeout(c.Request.Context(), loginTimeout)
	defer cancel()

	user, err := h.authStore.GetUserByUsername(ctx, req.Username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Internal server error",
		})
		return
	}

	if errors.Is(err, pgx.ErrNoRows) {
		userExists = false
		passwordHash = h.dummyPasswordHash
	} else {
		userExists = true
		passwordHash = user.Password
	}

	// Timing attack prevention: Always perform bcrypt comparison regardless of user existence.
	// This ensures consistent response time whether user exists or not.
	passwordErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))

	if !userExists || passwordErr != nil {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Code:    http.StatusForbidden,
			Message: "Invalid username or password",
		})
		return
	}

	token, err := auth.GenerateToken(user.ID, h.jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token: token,
		User: LoginUser{
			Username: user.Username,
		},
	})
}

// Logout handles user logout by validating the JWT token and returning 204 No Content.
// Token validation is performed by the AuthMiddleware, so this handler only needs to
// return success. Since JWT is stateless, the actual token cleanup is handled by the client.
func (h *AuthHandler) Logout(c *gin.Context) {
	// Token has already been validated by AuthMiddleware
	// User ID is available in context if needed: c.Get("user_id")
	c.Status(http.StatusNoContent)
}

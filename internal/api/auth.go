package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/auth"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/middleware"
	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/repository"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	// loginTimeout is the maximum duration for database operations during login.
	loginTimeout = 5 * time.Second
)

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

// AuthHandler handles authentication-related HTTP requests.
type AuthHandler struct {
	authRepo  repository.AuthRepository
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
func NewAuthHandler(authRepo repository.AuthRepository, jwtSecret string, opts ...AuthHandlerOption) (*AuthHandler, error) {
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
		authRepo:          authRepo,
		jwtSecret:         jwtSecret,
		dummyPasswordHash: string(hash),
	}, nil
}

// RegisterRoutes registers authentication routes to the router.
func (h *AuthHandler) RegisterRoutes(router *gin.Engine) {
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", h.Login)
		authGroup.POST("/logout", middleware.AuthRequired(h.jwtSecret), h.Logout)
	}
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

	user, err := h.authRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		// Handle user not found (use dummy hash for timing attack prevention)
		if errors.Is(err, repository.ErrUserNotFound) {
			userExists = false
			passwordHash = h.dummyPasswordHash
		} else {
			// All other errors are treated as internal server errors
			// TODO: [HPB-211] Add proper logging here to capture the actual error for debugging
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
			})
			return
		}
	} else {
		userExists = true
		passwordHash = user.Password
	}

	// Timing attack prevention: Always perform bcrypt comparison regardless of user existence.
	// This ensures consistent response time whether user exists or not.
	passwordErr := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))

	if !userExists || passwordErr != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Code:    http.StatusUnauthorized,
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

// Logout handles user logout by returning 204 No Content.
// Token validation is performed by the AuthRequired middleware, so this handler only needs to
// return success. Since JWT is stateless, the actual token cleanup is handled by the client.
func (h *AuthHandler) Logout(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

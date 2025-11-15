package middleware

import (
	"net/http"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/auth"
	"github.com/gin-gonic/gin"
)

// ErrorResponse represents the structure for error responses
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// AuthRequired validates JWT tokens and protects routes from unauthorized access.
func AuthRequired(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		// Extract Bearer token from Authorization header
		token, err := auth.ExtractBearerToken(authHeader)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{
				Code:    http.StatusUnauthorized,
				Message: "Invalid authorization format",
			})
			return
		}

		// Validate JWT token
		claims, err := auth.ValidateToken(token, jwtSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{
				Code:    http.StatusUnauthorized,
				Message: "Invalid token",
			})
			return
		}

		// Set user ID in context for downstream handlers
		c.Set("user_id", claims.UserID)

		c.Next()
	}
}

package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Goodidea-backend-camp/hpb-blog-backend/internal/auth"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthRequired(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	jwtSecret := "test-secret-key-with-sufficient-length"

	tests := []struct {
		name            string
		authHeader      string
		setupToken      func() string
		expectedStatus  int
		expectedMessage string
		expectUserIDSet bool
		expectedUserID  int32
	}{
		{
			name:       "Valid token - should pass",
			authHeader: "Bearer ",
			setupToken: func() string {
				token, err := auth.GenerateToken(123, jwtSecret)
				require.NoError(t, err)
				return token
			},
			expectedStatus:  http.StatusOK,
			expectUserIDSet: true,
			expectedUserID:  123,
		},
		{
			name:            "Missing Authorization header - should fail",
			authHeader:      "",
			setupToken:      func() string { return "" },
			expectedStatus:  http.StatusForbidden,
			expectedMessage: "Invalid authorization format",
			expectUserIDSet: false,
		},
		{
			name:       "Invalid format - missing Bearer prefix",
			authHeader: "Token ",
			setupToken: func() string {
				token, err := auth.GenerateToken(123, jwtSecret)
				require.NoError(t, err)
				return token
			},
			expectedStatus:  http.StatusForbidden,
			expectedMessage: "Invalid authorization format",
			expectUserIDSet: false,
		},
		{
			name:            "Empty token after Bearer prefix",
			authHeader:      "Bearer ",
			setupToken:      func() string { return "" },
			expectedStatus:  http.StatusForbidden,
			expectedMessage: "Invalid authorization format",
			expectUserIDSet: false,
		},
		{
			name:       "Expired token - should fail",
			authHeader: "Bearer ",
			setupToken: func() string {
				// Create an expired token using manual JWT construction
				claims := &auth.Claims{
					UserID: 123,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, err := token.SignedString([]byte(jwtSecret))
				require.NoError(t, err)
				return tokenString
			},
			expectedStatus:  http.StatusForbidden,
			expectedMessage: "Invalid token",
			expectUserIDSet: false,
		},
		{
			name:            "Invalid token signature - should fail",
			authHeader:      "Bearer ",
			setupToken:      func() string { return "invalid.jwt.token" },
			expectedStatus:  http.StatusForbidden,
			expectedMessage: "Invalid token",
			expectUserIDSet: false,
		},
		{
			name:       "Token signed with different secret - should fail",
			authHeader: "Bearer ",
			setupToken: func() string {
				token, err := auth.GenerateToken(123, "different-secret-key-with-length")
				require.NoError(t, err)
				return token
			},
			expectedStatus:  http.StatusForbidden,
			expectedMessage: "Invalid token",
			expectUserIDSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router with middleware
			router := gin.New()
			router.Use(AuthRequired(jwtSecret))

			// Add a test endpoint
			router.GET("/test", func(c *gin.Context) {
				userID, exists := c.Get("user_id")
				if exists {
					c.JSON(http.StatusOK, gin.H{"user_id": userID})
				} else {
					c.JSON(http.StatusOK, gin.H{"message": "success"})
				}
			})

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set Authorization header
			token := tt.setupToken()
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader+token)
			}

			// Perform request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse response
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			// Check error message if expected
			if tt.expectedMessage != "" {
				assert.Equal(t, tt.expectedMessage, response["message"])
				assert.Equal(t, float64(tt.expectedStatus), response["code"])
			}

			// Check if user_id was set correctly
			if tt.expectUserIDSet {
				assert.Equal(t, float64(tt.expectedUserID), response["user_id"])
			}
		})
	}
}

func TestAuthRequired_ContextPropagation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtSecret := "test-secret-key-with-sufficient-length"

	router := gin.New()
	router.Use(AuthRequired(jwtSecret))

	var capturedUserID int32
	router.GET("/test", func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		assert.True(t, exists, "user_id should exist in context")
		if exists {
			if uid, ok := userID.(int32); ok {
				capturedUserID = uid
			}
		}
		c.Status(http.StatusOK)
	})

	// Create valid token
	expectedUserID := int32(456)
	token, err := auth.GenerateToken(expectedUserID, jwtSecret)
	require.NoError(t, err)

	// Create and perform request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedUserID, capturedUserID)
}

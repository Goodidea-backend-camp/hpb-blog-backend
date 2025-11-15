package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityHeaders(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		expectedHeaders map[string]string
	}{
		{
			name: "All security headers should be set",
			expectedHeaders: map[string]string{
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"X-XSS-Protection":          "0",
				"Content-Security-Policy":   "default-src 'self'",
				"Referrer-Policy":           "strict-origin-when-cross-origin",
				"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router with middleware
			router := gin.New()
			router.Use(SecurityHeaders())

			// Add a test endpoint
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create and perform request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert status code
			assert.Equal(t, http.StatusOK, w.Code)

			// Assert all security headers are present and correct
			for headerName, expectedValue := range tt.expectedHeaders {
				actualValue := w.Header().Get(headerName)
				assert.Equal(t, expectedValue, actualValue, "Header %s should be set correctly", headerName)
			}
		})
	}
}

func TestSecurityHeaders_NextCalled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeaders())

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled, "Next handler should be called")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHostHeaderValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		expectedHost   string
		requestHost    string
		expectedStatus int
		expectError    bool
		errorMessage   string
	}{
		{
			name:           "Valid host - should pass",
			expectedHost:   "example.com",
			requestHost:    "example.com",
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Valid host with port - should pass",
			expectedHost:   "example.com:8080",
			requestHost:    "example.com:8080",
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Invalid host - should fail",
			expectedHost:   "example.com",
			requestHost:    "malicious.com",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMessage:   "Invalid host header",
		},
		{
			name:           "Mismatched port - should fail",
			expectedHost:   "example.com:8080",
			requestHost:    "example.com:9090",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMessage:   "Invalid host header",
		},
		{
			name:           "Empty expected host - should skip validation",
			expectedHost:   "",
			requestHost:    "any-host.com",
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Subdomain mismatch - should fail",
			expectedHost:   "example.com",
			requestHost:    "api.example.com",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
			errorMessage:   "Invalid host header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup router with middleware
			router := gin.New()
			router.Use(HostHeaderValidation(tt.expectedHost))

			// Add a test endpoint
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Host = tt.requestHost

			// Perform request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Assert status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse response
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			if tt.expectError {
				assert.Equal(t, tt.errorMessage, response["message"])
				assert.Equal(t, float64(tt.expectedStatus), response["code"])
			} else {
				assert.Equal(t, "success", response["message"])
			}
		})
	}
}

func TestHostHeaderValidation_EmptyConfig_NextCalled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(HostHeaderValidation(""))

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Host = "any-host.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled, "Next handler should be called when expectedHost is empty")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHostHeaderValidation_AbortPreventsNextHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(HostHeaderValidation("expected.com"))

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Host = "wrong.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.False(t, handlerCalled, "Next handler should NOT be called when host is invalid")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCombinedSecurityMiddlewares(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeaders())
	router.Use(HostHeaderValidation("example.com"))

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	t.Run("Valid request with both middlewares", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Host = "example.com"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should pass both middlewares
		assert.Equal(t, http.StatusOK, w.Code)

		// Security headers should be set
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	})

	t.Run("Invalid host with both middlewares", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Host = "malicious.com"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should fail at host validation
		assert.Equal(t, http.StatusBadRequest, w.Code)

		// Security headers should still be set (SecurityHeaders runs first)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	})
}

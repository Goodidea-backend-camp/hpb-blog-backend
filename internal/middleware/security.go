package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds security-related HTTP headers to all responses.
// Reference: https://gin-gonic.com/en/docs/examples/security-headers/
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking attacks
		c.Header("X-Frame-Options", "DENY")

		// Disable legacy XSS Auditor (modern browsers deprecate this, use CSP instead)
		c.Header("X-XSS-Protection", "0")

		// Content Security Policy to mitigate XSS and injection attacks
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Control referrer information leakage
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Restrict browser features
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Enforce HTTPS in all environments
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	}
}

// HostHeaderValidation validates the Host header to prevent
// SSRF (Server-Side Request Forgery) and open redirection attacks.
func HostHeaderValidation(expectedHost string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation if expectedHost is not configured
		if expectedHost == "" {
			c.Next()
			return
		}

		// Validate Host header matches expected domain
		if c.Request.Host != expectedHost {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
				Code:    http.StatusBadRequest,
				Message: "Invalid host header",
			})
			return
		}

		c.Next()
	}
}

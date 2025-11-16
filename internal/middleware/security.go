package middleware

import (
	"net/http"
	"slices"

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

// HostHeaderValidation validates the Host header to prevent SSRF and open redirection attacks.
func HostHeaderValidation(allowedHosts []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(allowedHosts) == 0 {
			// TODO: [HPB-211] Add proper logging here to capture the actual error for debugging
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{
				Code:    http.StatusInternalServerError,
				Message: "Internal server error",
			})
			return
		}

		// Check if request Host header matches any allowed host
		requestHost := c.Request.Host
		if slices.Contains(allowedHosts, requestHost) {
			c.Next()
			return
		}

		// If no match found, reject the request
		// TODO: [HPB-211] Add proper logging here to capture the actual error for debugging
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid authorization request",
		})
	}
}

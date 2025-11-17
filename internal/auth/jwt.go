package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// JWTExpiration is the JWT token expiration time
	JWTExpiration = 7 * 24 * time.Hour // 7 days
	// MinSecretLength is the minimum required length for JWT secret
	MinSecretLength = 32
	// BearerPrefix is the standard Bearer token prefix in Authorization header
	BearerPrefix = "Bearer "
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token expired")
	ErrEmptySecret       = errors.New("secret key cannot be empty")
	ErrSecretTooShort    = errors.New("secret key must be at least 32 characters")
	ErrMissingAuthHeader = errors.New("authorization header required")
	ErrInvalidAuthFormat = errors.New("invalid authorization format")
	ErrEmptyToken        = errors.New("token cannot be empty")
)

// Claims represents JWT claims with user identification.
type Claims struct {
	UserID int32 `json:"user_id"`
	jwt.RegisteredClaims
}

// ValidateSecret validates the strength of the JWT secret.
func ValidateSecret(secret string) error {
	if secret == "" {
		return ErrEmptySecret
	}
	if len(secret) < MinSecretLength {
		return ErrSecretTooShort
	}
	return nil
}

// ExtractBearerToken extracts and validates the JWT token from Authorization header.
// Returns the token string without the "Bearer " prefix.
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingAuthHeader
	}

	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return "", ErrInvalidAuthFormat
	}

	token := strings.TrimPrefix(authHeader, BearerPrefix)
	if strings.TrimSpace(token) == "" {
		return "", ErrEmptyToken
	}

	return token, nil
}

// GenerateToken creates a signed JWT token for the given user.
func GenerateToken(userID int32, secret string) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}

	expiresAt := time.Now().Add(JWTExpiration)

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken parses and validates a JWT token string.
func ValidateToken(tokenString string, secret string) (*Claims, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

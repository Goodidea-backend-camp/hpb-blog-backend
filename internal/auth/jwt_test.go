package auth

import (
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret"

func TestGenerateToken(t *testing.T) {
	userID := int32(123)

	token, err := GenerateToken(userID, testSecret)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateToken() returned empty token")
	}

	// Verify the generated token can be parsed
	claims, err := ValidateToken(token, testSecret)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("claims.UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestGenerateTokenWithEmptySecret(t *testing.T) {
	_, err := GenerateToken(123, "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("GenerateToken() error = %v, want %v", err, ErrEmptySecret)
	}
}

func TestValidateToken(t *testing.T) {
	userID := int32(456)

	token, err := GenerateToken(userID, testSecret)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := ValidateToken(token, testSecret)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("claims.UserID = %v, want %v", claims.UserID, userID)
	}
}

func TestValidateTokenExpired(t *testing.T) {
	// Create an expired token
	claims := &Claims{
		UserID: 789,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}

	_, err = ValidateToken(tokenString, testSecret)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrTokenExpired)
	}
}

func TestValidateTokenInvalid(t *testing.T) {
	invalidToken := "invalid.token.string"

	_, err := ValidateToken(invalidToken, testSecret)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
	}
}

func TestValidateTokenInvalidSignature(t *testing.T) {
	// Generate token with different secret
	wrongSecret := "wrong-secret-key-different-from-test-key"
	claims := &Claims{
		UserID: 999,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(wrongSecret))
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	_, err = ValidateToken(tokenString, testSecret)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
	}
}

func TestValidateTokenWithEmptySecret(t *testing.T) {
	_, err := ValidateToken("some.token.here", "")
	if !errors.Is(err, ErrEmptySecret) {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrEmptySecret)
	}
}

func TestValidateTokenAlgorithmNone(t *testing.T) {
	// Create a token with "none" algorithm (unsigned)
	claims := &Claims{
		UserID: 111,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Use the "none" algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to create none-algorithm token: %v", err)
	}

	// Should reject tokens with "none" algorithm
	_, err = ValidateToken(tokenString, testSecret)
	if err == nil {
		t.Error("ValidateToken() should reject token with 'none' algorithm")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
	}
}

func TestValidateTokenAlgorithmConfusion(t *testing.T) {
	// Try to use RS256 (RSA) instead of HS256 (HMAC)
	// This simulates an algorithm confusion attack

	// Manually construct an invalid token string with RS256 header
	// The validation should reject this because it's not HMAC
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"RS256","typ":"JWT"}
	fakeToken := header + ".eyJ1c2VyX2lkIjoyMjJ9.fakesignature"

	_, err := ValidateToken(fakeToken, testSecret)
	if err == nil {
		t.Error("ValidateToken() should reject token with RS256 algorithm")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
	}
}

func TestGenerateTokenBoundaryUserIDs(t *testing.T) {
	tests := []struct {
		name   string
		userID int32
	}{
		{"zero user ID", 0},
		{"negative user ID", -1},
		{"max int32", math.MaxInt32},
		{"min int32", math.MinInt32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateToken(tt.userID, testSecret)
			if err != nil {
				t.Fatalf("GenerateToken() error = %v", err)
			}

			claims, err := ValidateToken(token, testSecret)
			if err != nil {
				t.Fatalf("ValidateToken() error = %v", err)
			}

			if claims.UserID != tt.userID {
				t.Errorf("claims.UserID = %v, want %v", claims.UserID, tt.userID)
			}
		})
	}
}

func TestValidateTokenMalformedInputs(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"whitespace only", "   "},
		{"single segment", "onlyone"},
		{"two segments", "only.two"},
		{"four segments", "one.two.three.four"},
		{"special characters", "!@#$%^&*()"},
		{"unicode characters", "你好.世界.測試"},
		{"very long token", strings.Repeat("a", 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateToken(tt.token, testSecret)
			if err == nil {
				t.Errorf("ValidateToken() should return error for %q", tt.name)
			}
			// Should return either ErrInvalidToken or ErrEmptySecret
			if !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrEmptySecret) {
				t.Logf("ValidateToken() error = %v (acceptable)", err)
			}
		})
	}
}

func TestValidateTokenTimeBoundaries(t *testing.T) {
	t.Run("token at exact expiration", func(t *testing.T) {
		// Token expires right now
		claims := &Claims{
			UserID: 333,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(testSecret))
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Might be expired or might be valid depending on exact timing
		_, err = ValidateToken(tokenString, testSecret)
		// Either expired or valid is acceptable at exact boundary
		t.Logf("Token at exact expiration: %v", err)
	})

	t.Run("token issued in future", func(t *testing.T) {
		// Token issued 1 hour in the future
		futureTime := time.Now().Add(1 * time.Hour)
		claims := &Claims{
			UserID: 444,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(futureTime.Add(24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(futureTime),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(testSecret))
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Current implementation doesn't check IssuedAt, so this should succeed
		// This is a potential vulnerability to document
		_, err = ValidateToken(tokenString, testSecret)
		if err != nil {
			t.Logf("Future-dated token rejected: %v (good security practice)", err)
		} else {
			t.Logf("Future-dated token accepted (consider adding IssuedAt validation)")
		}
	})

	t.Run("token with missing ExpiresAt", func(t *testing.T) {
		// Token without expiration
		claims := &Claims{
			UserID: 555,
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now()),
				// ExpiresAt is not set
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(testSecret))
		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Current implementation might accept tokens without expiration
		_, err = ValidateToken(tokenString, testSecret)
		if err != nil {
			t.Logf("Token without expiration rejected: %v (good security)", err)
		} else {
			t.Logf("Token without expiration accepted (consider requiring ExpiresAt)")
		}
	})
}

func TestConcurrentTokenOperations(t *testing.T) {
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // Generate and Validate

	// Test concurrent token generation
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			userID := int32(id) // #nosec G115 -- id is bounded by numGoroutines (100), well within int32 range
			token, err := GenerateToken(userID, testSecret)
			if err != nil {
				t.Errorf("Concurrent GenerateToken() failed: %v", err)
				return
			}
			if token == "" {
				t.Error("Concurrent GenerateToken() returned empty token")
			}
		}(i)
	}

	// Test concurrent token validation
	testToken, err := GenerateToken(999, testSecret)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := ValidateToken(testToken, testSecret)
			if err != nil {
				t.Errorf("Concurrent ValidateToken() failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

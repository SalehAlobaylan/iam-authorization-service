package utils

import (
	"fmt"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims represents JWT access token claims with RBAC information.
type AccessTokenClaims struct {
	UserID      string                   `json:"user_id"`
	Email       string                   `json:"email"`
	Roles       []string                 `json:"roles"`
	IsAdmin     bool                     `json:"is_admin"`
	Permissions []models.PermissionClaim `json:"permissions"`
	jwt.RegisteredClaims
}

// GenerateAccessToken generates a signed JWT access token for the given user.
//
//   - user:       the authenticated user model
//   - roles:      list of role names assigned to the user
//   - permissions: flattened permission claims (resource + actions)
//   - secret:     HMAC secret used to sign the token
//   - ttl:        time-to-live in seconds
func GenerateAccessToken(
	user models.User,
	roles []string,
	permissions []models.PermissionClaim,
	secret string,
	ttl int,
) (string, error) {
	isAdmin := false
	for _, r := range roles {
		if r == "admin" {
			isAdmin = true
			break
		}
	}

	now := time.Now()
	claims := AccessTokenClaims{
		UserID:      user.ID.String(),
		Email:       user.Email,
		Roles:       roles,
		IsAdmin:     isAdmin,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "task-manager",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateRefreshToken generates a new opaque refresh token identifier.
// Uses UUIDv4 for compatibility with the existing tokens table (UUID column).
func GenerateRefreshToken() (string, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// ValidateAccessToken parses and validates a JWT access token string and
// returns the embedded AccessTokenClaims on success.
func ValidateAccessToken(tokenString, secret string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&AccessTokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AccessTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

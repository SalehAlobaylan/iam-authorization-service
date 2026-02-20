package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims represents JWT access token claims with RBAC information.
type AccessTokenClaims struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	TenantID    string   `json:"tenant_id"`
	Role        string   `json:"role"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	IsAdmin     bool     `json:"is_admin,omitempty"` // kept for compatibility
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
	userID string,
	email string,
	tenantID string,
	primaryRole string,
	roles []string,
	permissions []string,
	secret string,
	ttl int,
	issuer string,
	audience string,
) (string, error) {
	now := time.Now()
	jti, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	isAdmin := false
	for _, r := range roles {
		if strings.EqualFold(r, "admin") {
			isAdmin = true
			break
		}
	}

	claims := AccessTokenClaims{
		UserID:      userID,
		Email:       email,
		TenantID:    tenantID,
		Role:        primaryRole,
		Roles:       roles,
		Permissions: permissions,
		IsAdmin:     isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    issuer,
			Subject:   userID,
			ID:        jti.String(),
		},
	}
	if audience != "" {
		claims.Audience = []string{audience}
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

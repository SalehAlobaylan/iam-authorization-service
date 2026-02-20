package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"

	"gorm.io/gorm"
)

// TokenRepository manages persistence of refresh tokens.
// It uses the existing tokens table (see database-migrations) and does not yet
// model a separate "revoked" flag; revocation is handled by deletion for now.
type TokenRepository struct {
	db *gorm.DB
}

// NewTokenRepository creates a new TokenRepository bound to the given *gorm.DB.
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// Create inserts a new refresh token record.
func (r *TokenRepository) Create(token *models.Token) error {
	return r.db.Create(token).Error
}

// GetByRefreshToken looks up a token row by its refresh_token column.
func (r *TokenRepository) GetByRefreshToken(refreshToken string) (*models.Token, error) {
	var token models.Token
	if err := r.db.Where("refresh_token = ?", refreshToken).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}
	return &token, nil
}

// Revoke removes a single token row for the given refresh token.
func (r *TokenRepository) Revoke(refreshToken string) error {
	return r.db.Where("refresh_token = ?", refreshToken).Delete(&models.Token{}).Error
}

// DeleteByRefreshToken is kept as an alias for compatibility.
func (r *TokenRepository) DeleteByRefreshToken(refreshToken string) error {
	return r.Revoke(refreshToken)
}

// DeleteExpired removes tokens whose expires_at is in the past.
func (r *TokenRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).
		Delete(&models.Token{}).Error
}

// RevokeAllUserTokens removes all tokens belonging to a specific user.
func (r *TokenRepository) RevokeAllUserTokens(userID string) error {
	return r.db.Where("user_id = ?", userID).
		Delete(&models.Token{}).Error
}

// DeleteAllUserTokens is kept as an alias for compatibility.
func (r *TokenRepository) DeleteAllUserTokens(userID string) error {
	return r.RevokeAllUserTokens(userID)
}

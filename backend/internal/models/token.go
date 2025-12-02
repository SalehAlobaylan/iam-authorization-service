package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type Token struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	UserID       uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;column:user_id"`
	RefreshToken uuid.UUID      `json:"refresh_token" gorm:"type:uuid;not null;column:refresh_token"`
	ExpiresAt    time.Time      `json:"expires_at" gorm:"not null;column:expires_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// TableName overrides the default table name used by GORM.
func (Token) TableName() string {
	return "tokens"
}

// BeforeCreate ensures a UUID primary key is set for new Token records.
func (t *Token) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		t.ID = id
	}
	return nil
}

// TokenPair represents an access/refresh token pair returned to clients.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// RefreshTokenRequest captures the payload for requesting a new access token.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

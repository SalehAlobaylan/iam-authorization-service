package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type PasswordReset struct {
	ID     uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	UserID uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	// Token is delivery-only. New credentials are persisted only through
	// TokenDigest; the legacy token column remains readable during the rollout
	// so links issued before the migration can still be consumed.
	Token       string     `json:"-" gorm:"-"`
	TokenDigest string     `json:"-" gorm:"size:64;uniqueIndex;column:token_digest"`
	ExpiresAt   time.Time  `json:"expires_at" gorm:"not null"`
	UsedAt      *time.Time `json:"used_at"`
	CreatedAt   time.Time  `json:"created_at"`

	User User `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (PasswordReset) TableName() string {
	return "password_resets"
}

func (p *PasswordReset) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		p.ID = id
	}
	return nil
}

func (p *PasswordReset) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

func (p *PasswordReset) IsUsed() bool {
	return p.UsedAt != nil
}

// ForgotPasswordRequest captures the request payload for initiating a password reset.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest captures the request payload for completing a password reset.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=4"`
}

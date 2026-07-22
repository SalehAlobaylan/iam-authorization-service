package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type EmailVerification struct {
	ID     uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	UserID uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	// Token is delivery-only. New credentials are persisted only through
	// TokenDigest; the legacy token column remains readable during the rollout
	// so links issued before the migration can still be consumed.
	Token       string     `json:"-" gorm:"-"`
	TokenDigest string     `json:"-" gorm:"size:64;uniqueIndex;column:token_digest"`
	ExpiresAt   time.Time  `json:"expires_at" gorm:"not null"`
	VerifiedAt  *time.Time `json:"verified_at"`
	CreatedAt   time.Time  `json:"created_at"`

	User User `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (EmailVerification) TableName() string {
	return "email_verifications"
}

func (e *EmailVerification) BeforeCreate(tx *gorm.DB) error {
	if e.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		e.ID = id
	}
	return nil
}

func (e *EmailVerification) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type EmailVerification struct {
	ID         uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	UserID     uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	Token      string     `json:"-" gorm:"size:255;not null;uniqueIndex"`
	ExpiresAt  time.Time  `json:"expires_at" gorm:"not null"`
	VerifiedAt *time.Time `json:"verified_at"`
	CreatedAt  time.Time  `json:"created_at"`

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

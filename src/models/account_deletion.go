package models

import (
	"time"

	"github.com/gofrs/uuid"
)

// AccountDeletionRequest is IAM's durable, one-way deletion workflow record.
// The email snapshot exists only until post-completion confirmation is sent.
type AccountDeletionRequest struct {
	ID                   uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID               uuid.UUID  `gorm:"type:uuid;uniqueIndex;not null"`
	TenantID             string     `gorm:"type:varchar(64);not null"`
	ConfirmationEmail    string     `gorm:"type:varchar(255);not null"`
	Status               string     `gorm:"type:varchar(24);not null;index"`
	AttemptCount         int        `gorm:"not null;default:0"`
	LastError            *string    `gorm:"type:text"`
	ProcessingStartedAt  *time.Time `gorm:"index"`
	ProductDataDeletedAt *time.Time `gorm:"index"`
	IAMUserDeletedAt     *time.Time `gorm:"index"`
	CompletedAt          *time.Time `gorm:"index"`
	CreatedAt            time.Time  `gorm:"autoCreateTime"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime"`
}

func (AccountDeletionRequest) TableName() string { return "account_deletion_requests" }

func (r *AccountDeletionRequest) BeforeCreate() error {
	if r.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		r.ID = id
	}
	return nil
}

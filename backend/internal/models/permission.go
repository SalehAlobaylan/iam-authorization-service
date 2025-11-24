package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type Permission struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	Resource    string         `json:"resource" gorm:"size:50;not null;uniqueIndex:idx_permissions_resource_action"`
	Action      string         `json:"action" gorm:"size:50;not null;uniqueIndex:idx_permissions_resource_action"`
	Description string         `json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}



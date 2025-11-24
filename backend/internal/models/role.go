package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type Role struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	Name        string         `json:"name" gorm:"size:50;not null;unique"`
	Description string         `json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}



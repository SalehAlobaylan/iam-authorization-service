package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

type Task struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Description string         `json:"description"`
	Status      string         `json:"status" gorm:"size:50;not null;default:'pending'"`
	Priority    string         `json:"priority" gorm:"size:20;not null;default:'medium'"`
	OwnerID     uuid.UUID      `json:"owner_id" gorm:"type:uuid;not null;column:owner_id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
	DueDate     *time.Time     `json:"due_date" gorm:"column:due_date"`
}



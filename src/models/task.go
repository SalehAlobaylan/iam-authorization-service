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

	// Association to the owning user.
	Owner User `json:"-" gorm:"foreignKey:OwnerID;constraint:OnDelete:CASCADE"`
}

// TableName overrides the default table name used by GORM.
func (Task) TableName() string {
	return "tasks"
}

// BeforeCreate ensures a UUID primary key is set for new Task records.
func (t *Task) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		t.ID = id
	}
	return nil
}

// CreateTaskRequest captures the payload for creating a new task.
type CreateTaskRequest struct {
	Title       string     `json:"title" binding:"required"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	Priority    string     `json:"priority"`
	OwnerID     string     `json:"owner_id,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
}

// UpdateTaskRequest captures the payload for partially updating a task.
type UpdateTaskRequest struct {
	Title       *string    `json:"title,omitempty"`
	Description *string    `json:"description,omitempty"`
	Status      *string    `json:"status,omitempty"`
	Priority    *string    `json:"priority,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
}

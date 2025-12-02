package models

import (
	"time"

	"github.com/gofrs/uuid"
)

type UserRole struct {
	UserID     uuid.UUID `json:"user_id" gorm:"type:uuid;primaryKey;column:user_id"`
	RoleID     uuid.UUID `json:"role_id" gorm:"type:uuid;primaryKey;column:role_id"`
	AssignedAt time.Time `json:"assigned_at" gorm:"column:assigned_at"`
}

// TableName overrides the default table name used by GORM.
func (UserRole) TableName() string {
	return "user_roles"
}

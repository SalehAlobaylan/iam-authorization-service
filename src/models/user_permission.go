package models

import (
	"time"

	"github.com/gofrs/uuid"
)

// UserPermission stores direct per-user permission grants.
type UserPermission struct {
	UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
	AssignedAt   time.Time `json:"assigned_at" gorm:"autoCreateTime"`
}

// TableName overrides the default table name used by GORM.
func (UserPermission) TableName() string {
	return "user_permissions"
}

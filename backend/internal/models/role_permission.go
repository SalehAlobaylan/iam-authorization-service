package models

import (
	"time"

	"github.com/gofrs/uuid"
)

type RolePermission struct {
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;primaryKey;column:role_id"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey;column:permission_id"`
	AssignedAt   time.Time `json:"assigned_at" gorm:"column:assigned_at"`
}



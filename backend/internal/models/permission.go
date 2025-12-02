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

	// Associations
	Roles []Role `json:"-" gorm:"many2many:role_permissions;"`
}

// TableName overrides the default table name used by GORM.
func (Permission) TableName() string {
	return "permissions"
}

// BeforeCreate ensures a UUID primary key is set for new Permission records.
func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		p.ID = id
	}
	return nil
}

// PermissionClaim represents a flattened permission entry that is embedded
// into JWT access tokens. It groups all allowed actions for a given resource.
// Example:
//   { "resource": "task", "actions": ["read", "write", "delete"] }
type PermissionClaim struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}



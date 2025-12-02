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

	Users       []User       `json:"-" gorm:"many2many:user_roles;"`
	Permissions []Permission `json:"-" gorm:"many2many:role_permissions;"`
}

// TableName overrides the default table name used by GORM.
func (Role) TableName() string {
	return "roles"
}

// BeforeCreate ensures a UUID primary key is set for new Role records.
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		r.ID = id
	}
	return nil
}


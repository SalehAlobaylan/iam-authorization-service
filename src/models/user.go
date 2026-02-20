package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// User represents an application user persisted in the "users" table.
// It stores a hashed password (never exposed via JSON) and tracks
// associations to tokens, roles, and tasks for RBAC and ownership.
type User struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	Username     string         `json:"username" gorm:"size:255;not null;unique"`
	Email        string         `json:"email" gorm:"size:255;not null;unique"`
	PasswordHash string         `json:"-" gorm:"size:255;not null;column:password"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Associations
	Tokens []Token `json:"-" gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Roles  []Role  `json:"-" gorm:"many2many:user_roles;"`
	Tasks  []Task  `json:"-" gorm:"foreignKey:OwnerID;constraint:OnDelete:CASCADE"`
}

// TableName overrides the default table name used by GORM.
func (User) TableName() string {
	return "users"
}

// BeforeCreate ensures a UUID primary key is set for new User records when
// one is not already provided by the caller.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return err
		}
		u.ID = id
	}
	return nil
}

// RegisterRequest captures the request payload for user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// LoginRequest captures the request payload for user login.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents the token pair and expiry returned after login.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

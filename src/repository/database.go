package repository

import "gorm.io/gorm"

// Repositories groups all concrete repository types so they can be passed
// around together (for example into services or a server/router setup).
// This keeps wiring at the application boundary simple and explicit.
type Repositories struct {
	User       *UserRepository
	Token      *TokenRepository
	Role       *RoleRepository
	Permission *PermissionRepository
}

// NewRepositories constructs a Repositories bundle from a shared *gorm.DB.
func NewRepositories(db *gorm.DB) *Repositories {
	return &Repositories{
		User:       NewUserRepository(db),
		Token:      NewTokenRepository(db),
		Role:       NewRoleRepository(db),
		Permission: NewPermissionRepository(db),
	}
}

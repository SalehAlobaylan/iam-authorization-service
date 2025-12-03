package repositories

import (
	"errors"
	"fmt"

	"task-manager/backend/internal/models"
	"task-manager/backend/internal/utils"

	"gorm.io/gorm"
)

// RoleRepository provides query helpers around roles and user-role mappings.
type RoleRepository struct {
	db *gorm.DB
}

// NewRoleRepository creates a new RoleRepository bound to the given *gorm.DB.
func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// GetByName retrieves a role by its unique name.
func (r *RoleRepository) GetByName(name string) (*models.Role, error) {
	var role models.Role
	if err := r.db.Where("name = ?", name).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("role not found")
		}
		return nil, err
	}
	return &role, nil
}

// GetUserRoles returns all roles assigned to the given user via user_roles.
func (r *RoleRepository) GetUserRoles(userID string) ([]models.Role, error) {
	var roles []models.Role
	if err := r.db.Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

// AssignRoleToUser creates (or ensures existence of) a user_roles mapping.
func (r *RoleRepository) AssignRoleToUser(userID, roleID string) error {
	userUUID, err := utils.ParseUUID(userID)
	if err != nil {
		return err
	}
	roleUUID, err := utils.ParseUUID(roleID)
	if err != nil {
		return err
	}

	userRole := models.UserRole{UserID: userUUID, RoleID: roleUUID}
	return r.db.Where("user_id = ? AND role_id = ?", userRole.UserID, userRole.RoleID).
		FirstOrCreate(&userRole).Error
}

// RemoveRoleFromUser deletes a single user_roles mapping.
func (r *RoleRepository) RemoveRoleFromUser(userID, roleID string) error {
	return r.db.Where("user_id = ? AND role_id = ?", userID, roleID).
		Delete(&models.UserRole{}).Error
}

// GetAll returns all roles in the system.
func (r *RoleRepository) GetAll() ([]models.Role, error) {
	var roles []models.Role
	if err := r.db.Find(&roles).Error; err != nil {
		return nil, err
	}
	return roles, nil
}

// Create inserts a new role row.
func (r *RoleRepository) Create(role *models.Role) error {
	return r.db.Create(role).Error
}



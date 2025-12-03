package repositories

import (
	"task-manager/backend/internal/models"
	"task-manager/backend/internal/utils"

	"gorm.io/gorm"
)

// PermissionRepository encapsulates lookups of permissions and their
// relationships to roles and users.
type PermissionRepository struct {
	db *gorm.DB
}

// NewPermissionRepository creates a new PermissionRepository.
func NewPermissionRepository(db *gorm.DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// GetRolePermissions retrieves all permissions directly attached to a role.
func (r *PermissionRepository) GetRolePermissions(roleID string) ([]models.Permission, error) {
	var permissions []models.Permission
	if err := r.db.Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", roleID).
		Find(&permissions).Error; err != nil {
		return nil, err
	}
	return permissions, nil
}

// GetUserPermissions retrieves all distinct permissions granted to a user via
// their roles.
func (r *PermissionRepository) GetUserPermissions(userID string) ([]models.Permission, error) {
	var permissions []models.Permission
	if err := r.db.
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
		Where("user_roles.user_id = ?", userID).
		Distinct().
		Find(&permissions).Error; err != nil {
		return nil, err
	}
	return permissions, nil
}

// GetAll retrieves all permissions in the system.
func (r *PermissionRepository) GetAll() ([]models.Permission, error) {
	var permissions []models.Permission
	if err := r.db.Find(&permissions).Error; err != nil {
		return nil, err
	}
	return permissions, nil
}

// AssignPermissionToRole links a permission to a role via role_permissions.
func (r *PermissionRepository) AssignPermissionToRole(roleID, permissionID string) error {
	roleUUID, err := utils.ParseUUID(roleID)
	if err != nil {
		return err
	}
	permUUID, err := utils.ParseUUID(permissionID)
	if err != nil {
		return err
	}

	rolePermission := models.RolePermission{
		RoleID:       roleUUID,
		PermissionID: permUUID,
	}
	return r.db.Where(
		"role_id = ? AND permission_id = ?",
		rolePermission.RoleID,
		rolePermission.PermissionID,
	).FirstOrCreate(&rolePermission).Error
}

// RemovePermissionFromRole removes a permission-role mapping.
func (r *PermissionRepository) RemovePermissionFromRole(roleID, permissionID string) error {
	return r.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&models.RolePermission{}).Error
}

// Create inserts a new permission row.
func (r *PermissionRepository) Create(permission *models.Permission) error {
	return r.db.Create(permission).Error
}



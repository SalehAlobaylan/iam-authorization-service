package repository

import (
	"fmt"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/utils"

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

	var directPermissions []models.Permission
	if err := r.db.
		Joins("JOIN user_permissions ON user_permissions.permission_id = permissions.id").
		Where("user_permissions.user_id = ?", userID).
		Distinct().
		Find(&directPermissions).Error; err != nil {
		return nil, err
	}

	merged := make(map[string]models.Permission, len(permissions)+len(directPermissions))
	for _, permission := range permissions {
		merged[permission.ID.String()] = permission
	}
	for _, permission := range directPermissions {
		merged[permission.ID.String()] = permission
	}

	result := make([]models.Permission, 0, len(merged))
	for _, permission := range merged {
		result = append(result, permission)
	}
	return result, nil
}

// GetByResourceAction retrieves a permission by resource/action key.
func (r *PermissionRepository) GetByResourceAction(resource, action string) (*models.Permission, error) {
	var permission models.Permission
	if err := r.db.Where("resource = ? AND action = ?", resource, action).First(&permission).Error; err != nil {
		return nil, err
	}
	return &permission, nil
}

// ReplaceUserPermissions replaces direct user permission mappings.
func (r *PermissionRepository) ReplaceUserPermissions(userID string, permissionIDs []string) error {
	userUUID, err := utils.ParseUUID(userID)
	if err != nil {
		return err
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userUUID).Delete(&models.UserPermission{}).Error; err != nil {
			return err
		}
		for _, permissionID := range permissionIDs {
			permissionUUID, parseErr := utils.ParseUUID(permissionID)
			if parseErr != nil {
				return parseErr
			}
			userPermission := models.UserPermission{
				UserID:       userUUID,
				PermissionID: permissionUUID,
				AssignedAt:   time.Now(),
			}
			if err := tx.Create(&userPermission).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// GetUserDirectPermissions retrieves direct permissions attached to a user.
func (r *PermissionRepository) GetUserDirectPermissions(userID string) ([]models.Permission, error) {
	var permissions []models.Permission
	if err := r.db.
		Joins("JOIN user_permissions ON user_permissions.permission_id = permissions.id").
		Where("user_permissions.user_id = ?", userID).
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
	if permission.Resource == "" || permission.Action == "" {
		return fmt.Errorf("resource and action are required")
	}
	return r.db.Create(permission).Error
}

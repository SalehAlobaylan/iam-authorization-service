// This file contains an idempotent seeding routine that creates baseline RBAC
// data: roles, permissions, and their mappings, and optionally assigns the
// 'admin' role to a default admin user when present.
//
// Invocation options:
//   - Programmatic: call Seed(db) after establishing the DB connection.
//   - Startup (development): set SEED_ON_STARTUP=true to seed on service start.
//   - HTTP (development): expose POST /api/v1/admin/seed guarded by
//     ALLOW_SEED_ENDPOINT=true and call the Seed handler.
//
// Important: Only enable seeding in development or tightly controlled
// environments. Prefer SQL migrations for schema management in production.
package database

import (
	"errors"
	"fmt"
	"time"

	"task-manager/backend/internal/models"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// Seed inserts default roles, permissions, role-permissions, and assigns the
// 'admin' role to an existing admin user when present. The operation is
// idempotent and safe to run multiple times.
func Seed(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}

	if err := seedRoles(db); err != nil {
		return err
	}
	if err := seedPermissions(db); err != nil {
		return err
	}
	if err := seedRolePermissions(db); err != nil {
		return err
	}
	if err := assignAdminRoleToDefaultUser(db); err != nil {
		return err
	}
	return nil
}

// seedRoles ensures baseline roles exist (user, admin).
func seedRoles(db *gorm.DB) error {
	defaultRoles := []models.Role{
		{ID: uuid.FromStringOrNil("11111111-1111-1111-1111-111111111111"), Name: "user", Description: "Regular user with basic permissions"},
		{ID: uuid.FromStringOrNil("22222222-2222-2222-2222-222222222222"), Name: "admin", Description: "Administrator with full access"},
	}
	for _, role := range defaultRoles {
		var existing models.Role
		err := db.Where("name = ?", role.Name).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := db.Create(&role).Error; err != nil {
				return fmt.Errorf("create role %s: %w", role.Name, err)
			}
		} else if err != nil {
			return fmt.Errorf("query role %s: %w", role.Name, err)
		}
	}
	return nil
}

// seedPermissions ensures baseline permissions exist for profile, user, and task resources.
func seedPermissions(db *gorm.DB) error {
	type permSeed struct {
		ID          string
		Resource    string
		Action      string
		Description string
	}
	items := []permSeed{
		{"33333333-3333-3333-3333-333333333331", "profile", "read", "View user profile"},
		{"33333333-3333-3333-3333-333333333332", "profile", "write", "Update user profile"},
		{"44444444-4444-4444-4444-444444444441", "user", "read", "View users"},
		{"44444444-4444-4444-4444-444444444442", "user", "write", "Update users"},
		{"44444444-4444-4444-4444-444444444443", "user", "delete", "Delete users"},
		{"55555555-5555-5555-5555-555555555551", "task", "read", "View tasks"},
		{"55555555-5555-5555-5555-555555555552", "task", "write", "Create/Update tasks"},
		{"55555555-5555-5555-5555-555555555553", "task", "delete", "Delete tasks"},
	}
	for _, it := range items {
		var existing models.Permission
		err := db.Where("resource = ? AND action = ?", it.Resource, it.Action).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			p := models.Permission{
				ID:          uuid.FromStringOrNil(it.ID),
				Resource:    it.Resource,
				Action:      it.Action,
				Description: it.Description,
			}
			if err := db.Create(&p).Error; err != nil {
				return fmt.Errorf("create permission %s:%s: %w", it.Resource, it.Action, err)
			}
		} else if err != nil {
			return fmt.Errorf("query permission %s:%s: %w", it.Resource, it.Action, err)
		}
	}
	return nil
}

// seedRolePermissions maps:
//   - 'user' role to a minimal set of permissions (profile read/write, task read/write)
//   - 'admin' role to all permissions
func seedRolePermissions(db *gorm.DB) error {
	// Map 'user' role to a subset of permissions
	var userRole models.Role
	if err := db.Where("name = ?", "user").First(&userRole).Error; err != nil {
		return fmt.Errorf("load role user: %w", err)
	}

	var allPerms []models.Permission
	if err := db.Find(&allPerms).Error; err != nil {
		return fmt.Errorf("load permissions: %w", err)
	}

	allowed := map[string]map[string]bool{
		"profile": {"read": true, "write": true},
		"task":    {"read": true, "write": true},
	}
	for _, p := range allPerms {
		if m, ok := allowed[p.Resource]; ok && m[p.Action] {
			rp := models.RolePermission{RoleID: userRole.ID, PermissionID: p.ID, AssignedAt: time.Now()}
			var existing models.RolePermission
			err := db.Where("role_id = ? AND permission_id = ?", rp.RoleID, rp.PermissionID).First(&existing).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if err := db.Create(&rp).Error; err != nil {
					return fmt.Errorf("map user role to permission %s:%s: %w", p.Resource, p.Action, err)
				}
			} else if err != nil {
				return fmt.Errorf("query role-permission for user: %w", err)
			}
		}
	}

	// Map 'admin' role to all permissions
	var adminRole models.Role
	if err := db.Where("name = ?", "admin").First(&adminRole).Error; err != nil {
		return fmt.Errorf("load role admin: %w", err)
	}
	for _, p := range allPerms {
		rp := models.RolePermission{RoleID: adminRole.ID, PermissionID: p.ID, AssignedAt: time.Now()}
		var existing models.RolePermission
		err := db.Where("role_id = ? AND permission_id = ?", rp.RoleID, rp.PermissionID).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if err := db.Create(&rp).Error; err != nil {
				return fmt.Errorf("map admin role to permission %s:%s: %w", p.Resource, p.Action, err)
			}
		} else if err != nil {
			return fmt.Errorf("query role-permission for admin: %w", err)
		}
	}
	return nil
}

// assignAdminRoleToDefaultUser assigns the 'admin' role to the existing default
// admin user (lookup by email) when present. If no such user exists, it exits
// silently.
func assignAdminRoleToDefaultUser(db *gorm.DB) error {
	// Existing admin inserted by SQL migration uses 'admin@gmail.com'
	var adminUser models.User
	if err := db.Where("email = ?", "admin@gmail.com").First(&adminUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// No default admin user present; skip silently
			return nil
		}
		return fmt.Errorf("load admin user: %w", err)
	}
	var adminRole models.Role
	if err := db.Where("name = ?", "admin").First(&adminRole).Error; err != nil {
		return fmt.Errorf("load admin role: %w", err)
	}
	ur := models.UserRole{UserID: adminUser.ID, RoleID: adminRole.ID, AssignedAt: time.Now()}
	var existing models.UserRole
	err := db.Where("user_id = ? AND role_id = ?", ur.UserID, ur.RoleID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := db.Create(&ur).Error; err != nil {
			return fmt.Errorf("assign admin role to default admin user: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("query user-role for default admin: %w", err)
	}
	return nil
}

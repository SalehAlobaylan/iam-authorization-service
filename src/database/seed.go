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
	"strings"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"

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

// seedRoles ensures baseline roles exist (user, agent, manager, admin).
func seedRoles(db *gorm.DB) error {
	defaultRoles := []models.Role{
		{ID: uuid.FromStringOrNil("11111111-1111-1111-1111-111111111111"), Name: "user", Description: "Regular user with basic permissions"},
		{ID: uuid.FromStringOrNil("22222222-2222-2222-2222-222222222222"), Name: "agent", Description: "Agent role with operational permissions"},
		{ID: uuid.FromStringOrNil("33333333-3333-3333-3333-333333333333"), Name: "manager", Description: "Manager role with elevated operational permissions"},
		{ID: uuid.FromStringOrNil("44444444-4444-4444-4444-444444444444"), Name: "admin", Description: "Administrator with full access"},
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

// seedPermissions ensures baseline permissions exist for platform resources.
func seedPermissions(db *gorm.DB) error {
	type permSeed struct {
		ID          string
		Resource    string
		Action      string
		Description string
	}
	items := []permSeed{
		{"55555555-5555-5555-5555-555555555551", "profile", "read", "View user profile"},
		{"55555555-5555-5555-5555-555555555552", "profile", "write", "Update user profile"},
		{"66666666-6666-6666-6666-666666666661", "user", "read", "View users"},
		{"66666666-6666-6666-6666-666666666662", "user", "write", "Update users"},
		{"66666666-6666-6666-6666-666666666663", "user", "delete", "Delete users"},
		{"77777777-7777-7777-7777-777777777771", "task", "read", "View tasks"},
		{"77777777-7777-7777-7777-777777777772", "task", "write", "Create/Update tasks"},
		{"77777777-7777-7777-7777-777777777773", "task", "delete", "Delete tasks"},
		{"88888888-8888-8888-8888-888888888881", "source", "read", "View content sources"},
		{"88888888-8888-8888-8888-888888888882", "source", "write", "Manage content sources"},
		{"88888888-8888-8888-8888-888888888883", "source", "delete", "Delete content sources"},
		{"99999999-9999-9999-9999-999999999991", "content", "read", "View content items"},
		{"99999999-9999-9999-9999-999999999992", "content", "write", "Manage content items"},
		{"99999999-9999-9999-9999-999999999993", "content", "delete", "Delete content items"},
		{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1", "crm", "read", "View CRM resources"},
		{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2", "crm", "write", "Manage CRM resources"},
		{"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3", "crm", "delete", "Delete CRM resources"},
		{"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1", "iam", "read", "View IAM users/roles/permissions"},
		{"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2", "iam", "write", "Manage IAM users/roles/permissions"},
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

// seedRolePermissions maps all permissions to roles based on access tiers.
func seedRolePermissions(db *gorm.DB) error {
	var roles []models.Role
	if err := db.Find(&roles).Error; err != nil {
		return fmt.Errorf("load roles: %w", err)
	}
	var allPerms []models.Permission
	if err := db.Find(&allPerms).Error; err != nil {
		return fmt.Errorf("load permissions: %w", err)
	}

	roleAllowList := map[string]map[string]bool{
		"user": {
			"profile:read":  true,
			"profile:write": true,
			"task:read":     true,
		},
		"agent": {
			"profile:read":  true,
			"profile:write": true,
			"task:read":     true,
			"task:write":    true,
			"source:read":   true,
			"content:read":  true,
			"crm:read":      true,
			"crm:write":     true,
		},
		"manager": {
			"profile:read":  true,
			"profile:write": true,
			"task:read":     true,
			"task:write":    true,
			"task:delete":   true,
			"user:read":     true,
			"source:read":   true,
			"source:write":  true,
			"content:read":  true,
			"content:write": true,
			"crm:read":      true,
			"crm:write":     true,
			"crm:delete":    true,
		},
	}
	for _, role := range roles {
		for _, p := range allPerms {
			permissionKey := fmt.Sprintf("%s:%s", strings.ToLower(p.Resource), strings.ToLower(p.Action))
			allowed := strings.EqualFold(role.Name, "admin")
			if !allowed {
				allowed = roleAllowList[role.Name][permissionKey]
			}
			if !allowed {
				continue
			}

			rp := models.RolePermission{RoleID: role.ID, PermissionID: p.ID, AssignedAt: time.Now()}
			var existing models.RolePermission
			err := db.Where("role_id = ? AND permission_id = ?", rp.RoleID, rp.PermissionID).First(&existing).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if err := db.Create(&rp).Error; err != nil {
					return fmt.Errorf("map %s role to permission %s: %w", role.Name, permissionKey, err)
				}
			} else if err != nil {
				return fmt.Errorf("query role-permission for %s: %w", role.Name, err)
			}
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

	if strings.TrimSpace(adminUser.TenantID) == "" {
		if err := db.Model(&models.User{}).
			Where("id = ?", adminUser.ID).
			Update("tenant_id", "default").Error; err != nil {
			return fmt.Errorf("update default admin tenant: %w", err)
		}
	}
	return nil
}

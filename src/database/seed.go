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
	"os"
	"strings"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/utils"

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

	if err := ensureDefaultAdminUser(db); err != nil {
		return err
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

func defaultAdminEmail() string {
	email := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_EMAIL")))
	if email == "" {
		email = "admin@gmail.com"
	}
	return email
}

func ensureDefaultAdminUser(db *gorm.DB) error {
	email := defaultAdminEmail()
	password := strings.TrimSpace(os.Getenv("ADMIN_PASSWORD"))
	if password == "" {
		password = "admin"
	}
	username := strings.TrimSpace(os.Getenv("ADMIN_USERNAME"))
	if username == "" {
		username = "admin"
	}
	tenantID := strings.TrimSpace(os.Getenv("DEFAULT_TENANT_ID"))
	if tenantID == "" {
		tenantID = "default"
	}

	var existing models.User
	err := db.Where("email = ?", email).First(&existing).Error
	if err == nil {
		if cmpErr := utils.ComparePassword(existing.PasswordHash, password); cmpErr != nil {
			hash, hashErr := utils.HashPassword(password)
			if hashErr != nil {
				return fmt.Errorf("hash default admin password: %w", hashErr)
			}
			if updateErr := db.Model(&models.User{}).
				Where("id = ?", existing.ID).
				Updates(map[string]interface{}{
					"password":          hash,
					"tenant_id":         tenantID,
					"email_verified":    true,
					"email_verified_at": time.Now(),
				}).Error; updateErr != nil {
				return fmt.Errorf("update default admin user password: %w", updateErr)
			}
		}
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("query default admin user: %w", err)
	}

	hash, err := utils.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash default admin password: %w", err)
	}

	now := time.Now()
	user := models.User{
		Username:        username,
		Email:           email,
		TenantID:        tenantID,
		PasswordHash:    hash,
		EmailVerified:   true,
		EmailVerifiedAt: &now,
	}

	if err := db.Create(&user).Error; err != nil {
		return fmt.Errorf("create default admin user: %w", err)
	}

	return nil
}

// seedRoles ensures baseline roles exist (user, agent, editor, manager, admin).
func seedRoles(db *gorm.DB) error {
	defaultRoles := []models.Role{
		{ID: uuid.FromStringOrNil("11111111-1111-1111-1111-111111111111"), Name: "user", Description: "Regular user with basic permissions"},
		{ID: uuid.FromStringOrNil("22222222-2222-2222-2222-222222222222"), Name: "agent", Description: "Agent role with operational permissions"},
		{ID: uuid.FromStringOrNil("22222222-2222-2222-2222-222222222223"), Name: "editor", Description: "Content editor with publishing permissions"},
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
		{"88888888-8888-8888-8888-888888888881", "source", "read", "View content sources"},
		{"88888888-8888-8888-8888-888888888882", "source", "write", "Manage content sources"},
		{"88888888-8888-8888-8888-888888888883", "source", "delete", "Delete content sources"},
		{"99999999-9999-9999-9999-999999999991", "content", "read", "View content items"},
		{"99999999-9999-9999-9999-999999999992", "content", "write", "Manage content items"},
		{"99999999-9999-9999-9999-999999999993", "content", "delete", "Delete content items"},
		{"99999999-9999-9999-9999-999999999994", "content", "publish", "Publish content items"},
		{"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1", "iam", "read", "View IAM users/roles/permissions"},
		{"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2", "iam", "write", "Manage IAM users/roles/permissions"},
		{"cccccccc-cccc-cccc-cccc-ccccccccccc1", "feed", "read", "View feeds"},
		{"cccccccc-cccc-cccc-cccc-ccccccccccc2", "feed", "manage", "Manage feed configuration"},
		{"dddddddd-dddd-dddd-dddd-ddddddddddd1", "aggregation", "read", "View aggregation jobs"},
		{"dddddddd-dddd-dddd-dddd-ddddddddddd2", "aggregation", "manage", "Manage aggregation jobs"},
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
			"feed:read":     true,
		},
		"agent": {
			"profile:read":  true,
			"profile:write": true,
			"source:read":   true,
			"content:read":  true,
			"feed:read":     true,
		},
		"editor": {
			"profile:read":    true,
			"profile:write":   true,
			"source:read":     true,
			"content:read":    true,
			"content:write":   true,
			"content:publish": true,
			"feed:read":       true,
		},
		"manager": {
			"profile:read":       true,
			"profile:write":      true,
			"user:read":          true,
			"source:read":        true,
			"source:write":       true,
			"content:read":       true,
			"content:write":      true,
			"content:delete":     true,
			"content:publish":    true,
			"feed:read":          true,
			"feed:manage":        true,
			"aggregation:read":   true,
			"aggregation:manage": true,
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
	adminEmail := defaultAdminEmail()
	var adminUser models.User
	if err := db.Where("email = ?", adminEmail).First(&adminUser).Error; err != nil {
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

package services

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type IAMService struct {
	userRepo *repository.UserRepository
	roleRepo *repository.RoleRepository
	permRepo *repository.PermissionRepository
}

func NewIAMService(
	userRepo *repository.UserRepository,
	roleRepo *repository.RoleRepository,
	permRepo *repository.PermissionRepository,
) *IAMService {
	return &IAMService{
		userRepo: userRepo,
		roleRepo: roleRepo,
		permRepo: permRepo,
	}
}

type IAMUserView struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	TenantID    string   `json:"tenant_id"`
	Role        string   `json:"role"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func (s *IAMService) ListRoles() ([]models.Role, error) {
	roles, err := s.roleRepo.GetAll()
	if err != nil {
		return nil, utils.InternalServerError("failed to fetch roles")
	}
	return roles, nil
}

func (s *IAMService) ListPermissions() ([]models.Permission, error) {
	permissions, err := s.permRepo.GetAll()
	if err != nil {
		return nil, utils.InternalServerError("failed to fetch permissions")
	}
	return permissions, nil
}

func (s *IAMService) ListUsers(tenantID string) ([]IAMUserView, error) {
	users, err := s.userRepo.GetAllByTenant(tenantID)
	if err != nil {
		return nil, utils.InternalServerError("failed to fetch users")
	}

	result := make([]IAMUserView, 0, len(users))
	for _, user := range users {
		view, viewErr := s.userView(user)
		if viewErr != nil {
			return nil, viewErr
		}
		result = append(result, view)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Email < result[j].Email
	})
	return result, nil
}

func (s *IAMService) GetUserRoles(userID, tenantID string) ([]models.Role, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, utils.NotFoundError("user not found")
	}
	if user.TenantID != tenantID {
		return nil, utils.ForbiddenError("cross-tenant role access is forbidden")
	}

	roles, err := s.roleRepo.GetUserRoles(userID)
	if err != nil {
		return nil, utils.InternalServerError("failed to fetch user roles")
	}
	return roles, nil
}

func (s *IAMService) UpdateUserRoles(userID, tenantID string, roleNames []string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return utils.NotFoundError("user not found")
	}
	if user.TenantID != tenantID {
		return utils.ForbiddenError("cross-tenant role mutation is forbidden")
	}

	if len(roleNames) == 0 {
		return utils.ValidationError("at least one role is required")
	}

	roleIDs := make([]string, 0, len(roleNames))
	seen := map[string]struct{}{}
	for _, roleName := range roleNames {
		name := strings.ToLower(strings.TrimSpace(roleName))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		role, roleErr := s.roleRepo.GetByName(name)
		if roleErr != nil {
			return utils.ValidationError(fmt.Sprintf("unknown role: %s", name))
		}
		roleIDs = append(roleIDs, role.ID.String())
	}
	if len(roleIDs) == 0 {
		return utils.ValidationError("at least one valid role is required")
	}
	if err := s.roleRepo.ReplaceUserRoles(userID, roleIDs); err != nil {
		return utils.InternalServerError("failed to update user roles")
	}
	return nil
}

func (s *IAMService) UpdateUserPermissions(userID, tenantID string, permissions []string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return utils.NotFoundError("user not found")
	}
	if user.TenantID != tenantID {
		return utils.ForbiddenError("cross-tenant permission mutation is forbidden")
	}

	permissionIDs := make([]string, 0, len(permissions))
	seen := map[string]struct{}{}
	for _, item := range permissions {
		resource, action, parseErr := parsePermission(item)
		if parseErr != nil {
			return utils.ValidationError(parseErr.Error())
		}
		key := resource + ":" + action
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		permission, getErr := s.permRepo.GetByResourceAction(resource, action)
		if getErr != nil {
			return utils.ValidationError(fmt.Sprintf("unknown permission: %s", key))
		}
		permissionIDs = append(permissionIDs, permission.ID.String())
	}

	if err := s.permRepo.ReplaceUserPermissions(userID, permissionIDs); err != nil {
		return utils.InternalServerError("failed to update user permissions")
	}
	return nil
}

func (s *IAMService) userView(user models.User) (IAMUserView, error) {
	roles, err := s.roleRepo.GetUserRoles(user.ID.String())
	if err != nil {
		return IAMUserView{}, utils.InternalServerError("failed to fetch user roles")
	}
	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, strings.ToLower(role.Name))
	}

	perms, err := s.permRepo.GetUserPermissions(user.ID.String())
	if err != nil {
		return IAMUserView{}, utils.InternalServerError("failed to fetch user permissions")
	}
	permissionSet := map[string]struct{}{}
	for _, permission := range perms {
		key := strings.ToLower(strings.TrimSpace(permission.Resource)) + ":" + strings.ToLower(strings.TrimSpace(permission.Action))
		permissionSet[key] = struct{}{}
	}
	permissionList := make([]string, 0, len(permissionSet))
	for key := range permissionSet {
		permissionList = append(permissionList, key)
	}
	sort.Strings(permissionList)

	return IAMUserView{
		ID:          user.ID.String(),
		Username:    user.Username,
		Email:       user.Email,
		TenantID:    user.TenantID,
		Role:        derivePrimaryRole(roleNames),
		Roles:       roleNames,
		Permissions: permissionList,
		CreatedAt:   user.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   user.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}

func parsePermission(permission string) (string, string, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(permission)), ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("permission must be in resource:action format")
	}
	return parts[0], parts[1], nil
}

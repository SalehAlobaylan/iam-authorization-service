package services

import (
	"strings"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type AuthzService struct {
	roleRepo *repository.RoleRepository
	permRepo *repository.PermissionRepository
}

func NewAuthzService(roleRepo *repository.RoleRepository, permRepo *repository.PermissionRepository) *AuthzService {
	return &AuthzService{
		roleRepo: roleRepo,
		permRepo: permRepo,
	}
}

func (s *AuthzService) IsAdmin(claims *utils.AccessTokenClaims) bool {
	if claims == nil {
		return false
	}
	if claims.IsAdmin {
		return true
	}
	for _, role := range claims.Roles {
		if role == "admin" {
			return true
		}
	}
	return false
}

func (s *AuthzService) HasRole(claims *utils.AccessTokenClaims, role string) bool {
	if claims == nil {
		return false
	}
	for _, candidate := range claims.Roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func (s *AuthzService) HasPermission(claims *utils.AccessTokenClaims, resource, action string) bool {
	if claims == nil {
		return false
	}
	if s.IsAdmin(claims) {
		return true
	}
	for _, perm := range claims.Permissions {
		if !strings.EqualFold(perm.Resource, resource) {
			continue
		}
		for _, allowedAction := range perm.Actions {
			if strings.EqualFold(allowedAction, action) {
				return true
			}
		}
	}
	return false
}

func (s *AuthzService) CanAccessTask(claims *utils.AccessTokenClaims, ownerID string) bool {
	if claims == nil {
		return false
	}
	return s.IsAdmin(claims) || claims.UserID == ownerID
}

func (s *AuthzService) CanAccessUser(claims *utils.AccessTokenClaims, targetUserID string) bool {
	if claims == nil {
		return false
	}
	return s.IsAdmin(claims) || claims.UserID == targetUserID
}

func (s *AuthzService) AssignRoleToUser(userID, roleName string) error {
	role, err := s.roleRepo.GetByName(roleName)
	if err != nil {
		return utils.NotFoundError("role not found")
	}
	if err := s.roleRepo.AssignRoleToUser(userID, role.ID.String()); err != nil {
		return utils.InternalServerError("failed to assign role")
	}
	return nil
}

func (s *AuthzService) GetUserRoles(userID string) ([]models.Role, error) {
	roles, err := s.roleRepo.GetUserRoles(userID)
	if err != nil {
		return nil, utils.InternalServerError("failed to get user roles")
	}
	return roles, nil
}

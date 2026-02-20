package services

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type AuthService struct {
	userRepo  *repository.UserRepository
	tokenRepo *repository.TokenRepository
	roleRepo  *repository.RoleRepository
	permRepo  *repository.PermissionRepository
	config    *config.Config
}

func NewAuthService(
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	roleRepo *repository.RoleRepository,
	permRepo *repository.PermissionRepository,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		roleRepo:  roleRepo,
		permRepo:  permRepo,
		config:    cfg,
	}
}

func (s *AuthService) Register(username, email, password, tenantID string) (*models.User, error) {
	if err := utils.ValidateEmail(email); err != nil {
		return nil, utils.ValidationError(err.Error())
	}
	if err := utils.ValidatePassword(password); err != nil {
		return nil, utils.ValidationError(err.Error())
	}

	email = strings.ToLower(strings.TrimSpace(email))
	username = strings.TrimSpace(utils.NormalizeUsername(username, email))
	if err := utils.ValidateUsername(username); err != nil {
		return nil, utils.ValidationError(err.Error())
	}

	if _, err := s.userRepo.GetByEmail(email); err == nil {
		return nil, utils.ValidationError("user already exists")
	}

	uniqueUsername := username
	for i := 1; i <= 10; i++ {
		if _, err := s.userRepo.GetByUsername(uniqueUsername); err != nil {
			break
		}
		uniqueUsername = fmt.Sprintf("%s-%d", username, i)
	}
	if _, err := s.userRepo.GetByUsername(uniqueUsername); err == nil {
		return nil, utils.ValidationError("username already exists")
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, utils.InternalServerError("failed to hash password")
	}

	user := &models.User{
		Username:     uniqueUsername,
		Email:        email,
		TenantID:     strings.TrimSpace(tenantID),
		PasswordHash: hashedPassword,
	}
	if user.TenantID == "" {
		user.TenantID = strings.TrimSpace(s.config.Tenancy.DefaultTenantID)
	}
	if user.TenantID == "" {
		user.TenantID = "default"
	}
	if err := s.userRepo.Create(user); err != nil {
		return nil, utils.InternalServerError("failed to create user")
	}

	defaultRole, err := s.roleRepo.GetByName("user")
	if err != nil {
		defaultRole = &models.Role{
			Name:        "user",
			Description: "Regular user",
		}
		if createErr := s.roleRepo.Create(defaultRole); createErr != nil {
			return nil, utils.InternalServerError("failed to create default role")
		}
	}
	if err := s.roleRepo.AssignRoleToUser(user.ID.String(), defaultRole.ID.String()); err != nil {
		return nil, utils.InternalServerError("failed to assign default role")
	}

	user.PasswordHash = ""
	return user, nil
}

func (s *AuthService) Login(email, password string) (*models.TokenPair, error) {
	user, err := s.userRepo.GetByEmail(strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return nil, utils.UnauthorizedError("invalid credentials")
	}
	if err := utils.ComparePassword(user.PasswordHash, password); err != nil {
		return nil, utils.UnauthorizedError("invalid credentials")
	}

	roles, err := s.roleRepo.GetUserRoles(user.ID.String())
	if err != nil {
		return nil, utils.InternalServerError("failed to load user roles")
	}
	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}
	roleNames = normalizeRoles(roleNames)

	allPermissions, err := s.permRepo.GetUserPermissions(user.ID.String())
	if err != nil {
		return nil, utils.InternalServerError("failed to load user permissions")
	}
	permissionClaims := buildPermissionClaims(allPermissions)
	primaryRole := derivePrimaryRole(roleNames)

	accessToken, err := utils.GenerateAccessToken(
		user.ID.String(),
		user.Email,
		user.TenantID,
		primaryRole,
		roleNames,
		permissionClaims,
		s.config.JWT.Secret,
		s.config.JWT.AccessTokenTTL,
		s.config.JWT.Issuer,
		s.config.JWT.Audience,
	)
	if err != nil {
		return nil, utils.InternalServerError("failed to generate access token")
	}
	refreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		return nil, utils.InternalServerError("failed to generate refresh token")
	}

	if err := s.tokenRepo.Create(&models.Token{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(s.config.JWT.RefreshTokenTTL) * time.Second),
	}); err != nil {
		return nil, utils.InternalServerError("failed to store refresh token")
	}

	return &models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    s.config.JWT.AccessTokenTTL,
	}, nil
}

func (s *AuthService) Refresh(refreshToken string) (*models.TokenPair, error) {
	token, err := s.tokenRepo.GetByRefreshToken(refreshToken)
	if err != nil {
		return nil, utils.UnauthorizedError("invalid refresh token")
	}
	if time.Now().After(token.ExpiresAt) {
		_ = s.tokenRepo.Revoke(refreshToken)
		return nil, utils.UnauthorizedError("refresh token has expired")
	}

	user, err := s.userRepo.GetByID(token.UserID.String())
	if err != nil {
		return nil, utils.UnauthorizedError("user not found")
	}

	roles, err := s.roleRepo.GetUserRoles(user.ID.String())
	if err != nil {
		return nil, utils.InternalServerError("failed to load user roles")
	}
	roleNames := make([]string, 0, len(roles))
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}
	roleNames = normalizeRoles(roleNames)

	allPermissions, err := s.permRepo.GetUserPermissions(user.ID.String())
	if err != nil {
		return nil, utils.InternalServerError("failed to load user permissions")
	}
	permissionClaims := buildPermissionClaims(allPermissions)
	primaryRole := derivePrimaryRole(roleNames)

	newAccessToken, err := utils.GenerateAccessToken(
		user.ID.String(),
		user.Email,
		user.TenantID,
		primaryRole,
		roleNames,
		permissionClaims,
		s.config.JWT.Secret,
		s.config.JWT.AccessTokenTTL,
		s.config.JWT.Issuer,
		s.config.JWT.Audience,
	)
	if err != nil {
		return nil, utils.InternalServerError("failed to generate access token")
	}
	newRefreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		return nil, utils.InternalServerError("failed to generate refresh token")
	}

	if err := s.tokenRepo.Revoke(refreshToken); err != nil {
		return nil, utils.InternalServerError("failed to revoke old refresh token")
	}
	if err := s.tokenRepo.Create(&models.Token{
		UserID:       user.ID,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(s.config.JWT.RefreshTokenTTL) * time.Second),
	}); err != nil {
		return nil, utils.InternalServerError("failed to store new refresh token")
	}

	return &models.TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    s.config.JWT.AccessTokenTTL,
	}, nil
}

func (s *AuthService) Logout(refreshToken string) error {
	if strings.TrimSpace(refreshToken) == "" {
		return utils.ValidationError("refresh token is required")
	}
	if err := s.tokenRepo.Revoke(refreshToken); err != nil {
		return utils.InternalServerError("failed to revoke refresh token")
	}
	return nil
}

func buildPermissionClaims(perms []models.Permission) []string {
	permissionMap := make(map[string]struct{})
	for _, perm := range perms {
		key := strings.ToLower(strings.TrimSpace(perm.Resource)) + ":" + strings.ToLower(strings.TrimSpace(perm.Action))
		permissionMap[key] = struct{}{}
	}

	claims := make([]string, 0, len(permissionMap))
	for permission := range permissionMap {
		claims = append(claims, permission)
	}
	sort.Strings(claims)
	return claims
}

func derivePrimaryRole(roles []string) string {
	priority := []string{"admin", "manager", "agent", "user"}
	normalized := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		normalized[strings.ToLower(strings.TrimSpace(role))] = struct{}{}
	}
	for _, role := range priority {
		if _, ok := normalized[role]; ok {
			return role
		}
	}
	if len(roles) > 0 {
		return strings.ToLower(strings.TrimSpace(roles[0]))
	}
	return "user"
}

func normalizeRoles(roles []string) []string {
	seen := make(map[string]struct{}, len(roles))
	normalized := make([]string, 0, len(roles))
	for _, role := range roles {
		name := strings.ToLower(strings.TrimSpace(role))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	sort.Strings(normalized)
	return normalized
}

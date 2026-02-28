package services

import (
	"strings"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type UserService struct {
	userRepo *repository.UserRepository
	authz    *AuthzService
}

func NewUserService(userRepo *repository.UserRepository, authz *AuthzService) *UserService {
	return &UserService{
		userRepo: userRepo,
		authz:    authz,
	}
}

func (s *UserService) GetProfile(claims *utils.AccessTokenClaims, userID string) (*models.User, error) {
	targetUserID := userID
	if targetUserID == "" {
		targetUserID = claims.UserID
	}
	if err := utils.ValidateUUID(targetUserID); err != nil {
		return nil, utils.ValidationError("invalid user id")
	}
	if !s.authz.CanAccessUser(claims, targetUserID) && !s.authz.HasPermission(claims, "user", "read") {
		return nil, utils.ForbiddenError("cannot access this user profile")
	}

	user, err := s.userRepo.GetByID(targetUserID)
	if err != nil {
		return nil, utils.NotFoundError("user not found")
	}
	user.PasswordHash = ""
	return user, nil
}

func (s *UserService) GetUsers(claims *utils.AccessTokenClaims) ([]models.User, error) {
	if !s.authz.HasPermission(claims, "user", "read") {
		return nil, utils.ForbiddenError("insufficient permission to view users")
	}

	users, err := s.userRepo.GetAll()
	if err != nil {
		return nil, utils.InternalServerError("failed to load users")
	}
	for i := range users {
		users[i].PasswordHash = ""
	}
	return users, nil
}

func (s *UserService) UpdateProfile(claims *utils.AccessTokenClaims, req models.UpdateProfileRequest) (*models.User, error) {
	if !s.authz.HasPermission(claims, "profile", "write") {
		return nil, utils.ForbiddenError("insufficient permission to update profile")
	}

	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		return nil, utils.NotFoundError("user not found")
	}

	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		if username == "" {
			return nil, utils.ValidationError("username cannot be empty")
		}
		if err := utils.ValidateUsername(username); err != nil {
			return nil, utils.ValidationError(err.Error())
		}
		existing, lookupErr := s.userRepo.GetByUsername(username)
		if lookupErr == nil && existing.ID != user.ID {
			return nil, utils.ValidationError("username already taken")
		}
		user.Username = username
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, utils.InternalServerError("failed to update profile")
	}
	user.PasswordHash = ""
	return user, nil
}

func (s *UserService) DeleteUser(claims *utils.AccessTokenClaims, userID string) error {
	if !s.authz.HasPermission(claims, "user", "delete") {
		return utils.ForbiddenError("insufficient permission to delete users")
	}
	if err := utils.ValidateUUID(userID); err != nil {
		return utils.ValidationError("invalid user id")
	}

	if _, err := s.userRepo.GetByID(userID); err != nil {
		return utils.NotFoundError("user not found")
	}
	if err := s.userRepo.Delete(userID); err != nil {
		return utils.InternalServerError("failed to delete user")
	}
	return nil
}

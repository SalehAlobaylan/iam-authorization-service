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

	if req.Bio != nil {
		bio := strings.TrimSpace(*req.Bio)
		if len(bio) > 500 {
			return nil, utils.ValidationError("bio must be at most 500 characters")
		}
		if bio == "" {
			user.Bio = nil
		} else {
			user.Bio = &bio
		}
	}

	if req.AvatarURL != nil {
		avatar := strings.TrimSpace(*req.AvatarURL)
		if avatar == "" {
			user.AvatarURL = nil
		} else {
			if len(avatar) > 2048 {
				return nil, utils.ValidationError("avatar_url is too long")
			}
			user.AvatarURL = &avatar
		}
	}

	if req.Interests != nil {
		// Normalize: trim, drop empties, dedupe, cap at 20.
		raw := *req.Interests
		seen := make(map[string]struct{}, len(raw))
		normalized := make([]string, 0, len(raw))
		for _, item := range raw {
			value := strings.TrimSpace(item)
			if value == "" {
				continue
			}
			if len(value) > 40 {
				return nil, utils.ValidationError("each interest must be at most 40 characters")
			}
			lower := strings.ToLower(value)
			if _, dup := seen[lower]; dup {
				continue
			}
			seen[lower] = struct{}{}
			normalized = append(normalized, value)
			if len(normalized) >= 20 {
				break
			}
		}
		user.Interests = normalized
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, utils.InternalServerError("failed to update profile")
	}
	user.PasswordHash = ""
	return user, nil
}

// ChangePassword updates the authenticated user's password after verifying
// the current one. Used by the Wahb-Platform settings page; admin password
// resets (without knowing the current password) go through the separate
// /auth/forgot-password + /auth/reset-password flow.
func (s *UserService) ChangePassword(claims *utils.AccessTokenClaims, currentPassword, newPassword string) error {
	if strings.TrimSpace(currentPassword) == "" || strings.TrimSpace(newPassword) == "" {
		return utils.ValidationError("current and new passwords are required")
	}
	if len(newPassword) < 4 {
		return utils.ValidationError("new password must be at least 4 characters")
	}
	if currentPassword == newPassword {
		return utils.ValidationError("new password must differ from the current one")
	}

	user, err := s.userRepo.GetByID(claims.UserID)
	if err != nil {
		return utils.NotFoundError("user not found")
	}
	if err := utils.ComparePassword(user.PasswordHash, currentPassword); err != nil {
		return utils.UnauthorizedError("current password is incorrect")
	}

	hashed, err := utils.HashPassword(newPassword)
	if err != nil {
		return utils.InternalServerError("failed to hash new password")
	}
	user.PasswordHash = hashed
	if err := s.userRepo.Update(user); err != nil {
		return utils.InternalServerError("failed to update password")
	}
	return nil
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

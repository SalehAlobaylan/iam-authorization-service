package services

import (
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type PasswordResetService struct {
	resetRepo *repository.PasswordResetRepository
	userRepo  *repository.UserRepository
	tokenRepo *repository.TokenRepository
	email     EmailSender
	cfg       *config.Config
}

func NewPasswordResetService(
	resetRepo *repository.PasswordResetRepository,
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	email EmailSender,
	cfg *config.Config,
) *PasswordResetService {
	return &PasswordResetService{
		resetRepo: resetRepo,
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		email:     email,
		cfg:       cfg,
	}
}

// ForgotPassword creates a reset token and sends a reset email.
// Always returns nil to avoid revealing whether the email exists.
func (s *PasswordResetService) ForgotPassword(email string) error {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Don't reveal whether the email exists
		return nil
	}

	// Clean up old tokens
	_ = s.resetRepo.DeleteByUserID(user.ID.String())

	token, err := uuid.NewV4()
	if err != nil {
		return utils.InternalServerError("failed to generate reset token")
	}

	reset := &models.PasswordReset{
		UserID:    user.ID,
		Token:     token.String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := s.resetRepo.Create(reset); err != nil {
		return utils.InternalServerError("failed to create reset token")
	}

	baseURL := s.cfg.Email.ResetBaseURL
	if baseURL == "" {
		baseURL = "http://localhost:3005"
	}
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token.String())

	subject := "Reset your password"
	body := fmt.Sprintf(`<h2>Password Reset</h2>
<p>Click the link below to reset your password:</p>
<p><a href="%s">Reset Password</a></p>
<p>This link expires in 1 hour.</p>
<p>If you did not request a password reset, you can ignore this email.</p>`, resetURL)

	if err := s.email.Send(user.Email, subject, body); err != nil {
		return utils.InternalServerError("failed to send reset email")
	}
	return nil
}

// ResetPassword validates the token and updates the user's password.
func (s *PasswordResetService) ResetPassword(token, newPassword string) error {
	if err := utils.ValidatePassword(newPassword); err != nil {
		return utils.ValidationError(err.Error())
	}

	reset, err := s.resetRepo.GetByToken(token)
	if err != nil {
		return utils.NotFoundError("invalid or expired reset token")
	}
	if reset.IsExpired() {
		return utils.ValidationError("reset token has expired")
	}
	if reset.IsUsed() {
		return utils.ValidationError("reset token has already been used")
	}

	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return utils.InternalServerError("failed to hash password")
	}

	user, err := s.userRepo.GetByID(reset.UserID.String())
	if err != nil {
		return utils.NotFoundError("user not found")
	}
	user.PasswordHash = hashedPassword
	if err := s.userRepo.Update(user); err != nil {
		return utils.InternalServerError("failed to update password")
	}

	// Invalidate all existing sessions: a password reset is the primary action
	// a user takes when they suspect compromise, so any refresh tokens issued
	// before the reset must be revoked. Mirrors UserService.ChangePassword.
	// (Already-issued stateless access tokens remain valid until they expire.)
	if err := s.tokenRepo.RevokeAllUserTokens(reset.UserID.String()); err != nil {
		return utils.InternalServerError("failed to revoke existing sessions")
	}

	now := time.Now()
	reset.UsedAt = &now
	if err := s.resetRepo.Update(reset); err != nil {
		return utils.InternalServerError("failed to update reset record")
	}

	// Clean up all reset tokens for this user
	_ = s.resetRepo.DeleteByUserID(reset.UserID.String())

	return nil
}

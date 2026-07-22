package services

import (
	"fmt"
	"log"
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
		// Match the nonexistent-account response. Provider health must not turn
		// this endpoint into an account-enumeration oracle.
		log.Printf("[email_delivery] type=password_reset result=pending error_type=%T", err)
		return nil
	}
	return nil
}

// ResetPassword validates the token and updates the user's password.
func (s *PasswordResetService) ResetPassword(token, newPassword string) error {
	if err := utils.ValidatePassword(newPassword); err != nil {
		return utils.ValidationError(err.Error())
	}

	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return utils.InternalServerError("failed to hash password")
	}

	consumed, err := s.resetRepo.ConsumeAndResetPassword(token, hashedPassword, time.Now())
	if err != nil {
		return utils.InternalServerError("failed to reset password")
	}
	if !consumed {
		return utils.ValidationError("invalid or expired reset token")
	}

	return nil
}

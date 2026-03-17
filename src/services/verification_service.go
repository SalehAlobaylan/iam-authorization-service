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

type VerificationService struct {
	verifyRepo *repository.VerificationRepository
	userRepo   *repository.UserRepository
	email      EmailSender
	cfg        *config.Config
}

func NewVerificationService(
	verifyRepo *repository.VerificationRepository,
	userRepo *repository.UserRepository,
	email EmailSender,
	cfg *config.Config,
) *VerificationService {
	return &VerificationService{
		verifyRepo: verifyRepo,
		userRepo:   userRepo,
		email:      email,
		cfg:        cfg,
	}
}

// SendVerification creates a verification token and sends a verification email.
func (s *VerificationService) SendVerification(userID, email string) error {
	token, err := uuid.NewV4()
	if err != nil {
		return utils.InternalServerError("failed to generate verification token")
	}

	userUUID, err := uuid.FromString(userID)
	if err != nil {
		return utils.ValidationError("invalid user id")
	}

	v := &models.EmailVerification{
		UserID:    userUUID,
		Token:     token.String(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.verifyRepo.Create(v); err != nil {
		return utils.InternalServerError("failed to create verification token")
	}

	baseURL := s.cfg.Email.VerificationBaseURL
	if baseURL == "" {
		baseURL = "http://localhost:3005"
	}
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", baseURL, token.String())

	subject := "Verify your email address"
	body := fmt.Sprintf(`<h2>Email Verification</h2>
<p>Click the link below to verify your email address:</p>
<p><a href="%s">Verify Email</a></p>
<p>This link expires in 24 hours.</p>
<p>If you did not create an account, you can ignore this email.</p>`, verifyURL)

	if err := s.email.Send(email, subject, body); err != nil {
		return utils.InternalServerError("failed to send verification email")
	}
	return nil
}

// VerifyEmail validates the token and marks the user's email as verified.
func (s *VerificationService) VerifyEmail(token string) error {
	v, err := s.verifyRepo.GetByToken(token)
	if err != nil {
		return utils.NotFoundError("invalid or expired verification token")
	}
	if v.IsExpired() {
		return utils.ValidationError("verification token has expired")
	}
	if v.VerifiedAt != nil {
		return utils.ValidationError("email already verified")
	}

	now := time.Now()
	v.VerifiedAt = &now
	if err := s.verifyRepo.Update(v); err != nil {
		return utils.InternalServerError("failed to update verification record")
	}

	user, err := s.userRepo.GetByID(v.UserID.String())
	if err != nil {
		return utils.NotFoundError("user not found")
	}
	user.EmailVerified = true
	user.EmailVerifiedAt = &now
	if err := s.userRepo.Update(user); err != nil {
		return utils.InternalServerError("failed to update user")
	}

	// Clean up all verification tokens for this user
	_ = s.verifyRepo.DeleteByUserID(v.UserID.String())

	return nil
}

// ResendVerification sends a new verification email to the user.
func (s *VerificationService) ResendVerification(email string) error {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Don't reveal whether the email exists
		return nil
	}
	if user.EmailVerified {
		return nil
	}

	// Clean up old tokens
	_ = s.verifyRepo.DeleteByUserID(user.ID.String())

	return s.SendVerification(user.ID.String(), user.Email)
}

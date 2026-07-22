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
	now := time.Now()
	consumed, err := s.verifyRepo.ConsumeAndVerifyUser(token, now)
	if err != nil {
		return utils.InternalServerError("failed to verify email")
	}
	if !consumed {
		return utils.ValidationError("invalid or expired verification token")
	}

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

	// Public recovery delivery must remain neutral when the provider is down;
	// otherwise a sender can enumerate registered, unverified accounts.
	if err := s.SendVerification(user.ID.String(), user.Email); err != nil {
		log.Printf("[email_delivery] type=verification result=pending error_type=%T", err)
	}
	return nil
}

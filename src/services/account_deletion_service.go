package services

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
	"gorm.io/gorm"
)

type AccountDeletionService struct {
	users    *repository.UserRepository
	tokens   *repository.TokenRepository
	requests *repository.AccountDeletionRepository
	cms      *CMSSuspensionClient
	email    EmailSender
}

func NewAccountDeletionService(users *repository.UserRepository, tokens *repository.TokenRepository, requests *repository.AccountDeletionRepository, cms *CMSSuspensionClient, email EmailSender) *AccountDeletionService {
	return &AccountDeletionService{users, tokens, requests, cms, email}
}

func (s *AccountDeletionService) Request(userID, password string) error {
	if s.cms == nil {
		return utils.NewAPIError(503, "account deletion is not configured")
	}
	user, err := s.users.GetByID(userID)
	if err != nil {
		return utils.NotFoundError("user not found")
	}
	if err := utils.ComparePassword(user.PasswordHash, password); err != nil {
		return utils.UnauthorizedError("password confirmation failed")
	}
	if existing, err := s.requests.GetByUserID(userID); err == nil {
		if existing.Status == "completed" {
			return utils.NotFoundError("user not found")
		}
		return nil
	} else if err != nil && err != gorm.ErrRecordNotFound {
		return utils.InternalServerError("failed to create deletion request")
	}
	now := time.Now().UTC()
	if err := s.users.SetSuspendedAt(userID, &now); err != nil {
		return utils.InternalServerError("failed to lock account")
	}
	if err := s.tokens.RevokeAllUserTokens(userID); err != nil {
		return utils.InternalServerError("failed to revoke account sessions")
	}
	if err := s.cms.Sync(context.Background(), userID, user.TenantID, true); err != nil {
		_ = s.users.SetSuspendedAt(userID, nil)
		return utils.NewAPIError(502, "account deletion could not be enforced")
	}
	if err := s.requests.Create(&models.AccountDeletionRequest{UserID: user.ID, TenantID: user.TenantID, ConfirmationEmail: user.Email, Status: "queued"}); err != nil {
		return utils.InternalServerError("failed to queue account deletion")
	}
	return nil
}

func (s *AccountDeletionService) Start() {
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		s.ProcessQueued()
		for range ticker.C {
			s.ProcessQueued()
		}
	}()
}
func (s *AccountDeletionService) ProcessQueued() {
	rows, err := s.requests.Queued()
	if err != nil {
		return
	}
	for i := range rows {
		s.process(&rows[i])
	}
}
func (s *AccountDeletionService) process(request *models.AccountDeletionRequest) {
	request.Status = "processing"
	request.AttemptCount++
	_ = s.requests.Save(request)
	if err := s.cms.DeleteProductData(context.Background(), request.UserID.String(), request.TenantID); err != nil {
		s.fail(request, err)
		return
	}
	if err := s.users.DeletePermanently(request.UserID.String()); err != nil {
		s.fail(request, err)
		return
	}
	if err := s.email.Send(request.ConfirmationEmail, "Your Wahb account has been deleted", "<p>Your Wahb account and product data have been deleted.</p>"); err != nil {
		s.fail(request, err)
		return
	}
	now := time.Now().UTC()
	request.Status = "completed"
	request.CompletedAt = &now
	request.LastError = nil
	request.ConfirmationEmail = ""
	_ = s.requests.Save(request)
}
func (s *AccountDeletionService) fail(request *models.AccountDeletionRequest, err error) {
	message := fmt.Sprintf("%T", err)
	request.Status = "failed"
	request.LastError = &message
	_ = s.requests.Save(request)
}

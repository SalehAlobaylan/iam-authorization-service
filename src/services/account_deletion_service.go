package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
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
	now := time.Now().UTC()
	_, created, err := s.requests.CreateAndLock(user, now)
	if err != nil {
		return utils.InternalServerError("failed to queue account deletion")
	}
	if created {
		// The durable request and local suspension are already committed. A CMS
		// failure must not re-enable the account; the worker retries the mirror
		// before deleting product data.
		if err := s.cms.Sync(context.Background(), userID, user.TenantID, true); err != nil {
			log.Printf("[account_deletion] suspension mirror pending user_id=%s error_type=%T", userID, err)
		}
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
	for range 20 {
		request, err := s.requests.ClaimNext(time.Now().UTC().Add(-5 * time.Minute))
		if err != nil || request == nil {
			return
		}
		s.process(request)
	}
}
func (s *AccountDeletionService) process(request *models.AccountDeletionRequest) {
	if err := s.cms.Sync(context.Background(), request.UserID.String(), request.TenantID, true); err != nil {
		s.fail(request, err)
		return
	}
	if request.ProductDataDeletedAt == nil {
		if err := s.cms.DeleteProductData(context.Background(), request.UserID.String(), request.TenantID); err != nil {
			s.fail(request, err)
			return
		}
		now := time.Now().UTC()
		if err := s.requests.MarkProductDataDeleted(request.ID.String(), now); err != nil {
			s.fail(request, err)
			return
		}
		request.ProductDataDeletedAt = &now
	}
	if request.IAMUserDeletedAt == nil {
		if err := s.users.DeletePermanently(request.UserID.String()); err != nil {
			s.fail(request, err)
			return
		}
		now := time.Now().UTC()
		if err := s.requests.MarkIAMUserDeleted(request.ID.String(), now); err != nil {
			s.fail(request, err)
			return
		}
		request.IAMUserDeletedAt = &now
	}
	now := time.Now().UTC()
	email := request.ConfirmationEmail
	if err := s.requests.Complete(request.ID.String(), now); err != nil {
		s.fail(request, err)
		return
	}
	// Confirmation delivery is non-retryable: the deletion has completed and a
	// failed mail must never cause irreversible product deletion to be replayed.
	if email != "" {
		if err := s.email.Send(email, "Your Wahb account has been deleted", "<p>Your Wahb account and product data have been deleted.</p>"); err != nil {
			log.Printf("[account_deletion] confirmation delivery failed request_id=%s error_type=%T", request.ID, err)
		}
	}
}
func (s *AccountDeletionService) fail(request *models.AccountDeletionRequest, err error) {
	message := fmt.Sprintf("%T", err)
	if saveErr := s.requests.Fail(request.ID.String(), message); saveErr != nil {
		log.Printf("[account_deletion] failed to persist retry state request_id=%s error_type=%T", request.ID, saveErr)
	}
}

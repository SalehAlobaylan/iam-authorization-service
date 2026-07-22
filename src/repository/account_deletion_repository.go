package repository

import (
	"errors"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AccountDeletionRepository struct{ db *gorm.DB }

func NewAccountDeletionRepository(db *gorm.DB) *AccountDeletionRepository {
	return &AccountDeletionRepository{db: db}
}
func (r *AccountDeletionRepository) Create(request *models.AccountDeletionRequest) error {
	return r.db.Create(request).Error
}

// CreateAndLock makes the user's local suspension, refresh-token revocation,
// and durable deletion request one database transaction. CMS synchronization is
// deliberately outside this transaction and retried by the deletion worker.
func (r *AccountDeletionRepository) CreateAndLock(
	user *models.User,
	now time.Time,
) (*models.AccountDeletionRequest, bool, error) {
	request := &models.AccountDeletionRequest{}
	created := false
	err := r.db.Transaction(func(tx *gorm.DB) error {
		candidate := &models.AccountDeletionRequest{
			UserID:            user.ID,
			TenantID:          user.TenantID,
			ConfirmationEmail: user.Email,
			Status:            "queued",
		}
		result := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "user_id"}}, DoNothing: true}).Create(candidate)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			if err := tx.Where("user_id = ?", user.ID).First(request).Error; err != nil {
				return err
			}
			return nil
		}

		if err := tx.Model(&models.User{}).Where("id = ?", user.ID).Update("suspended_at", now).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", user.ID).Delete(&models.Token{}).Error; err != nil {
			return err
		}
		*request = *candidate
		created = true
		return nil
	})
	return request, created, err
}
func (r *AccountDeletionRepository) GetByUserID(userID string) (*models.AccountDeletionRequest, error) {
	var row models.AccountDeletionRequest
	if err := r.db.Where("user_id = ?", userID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// ClaimNext atomically leases one queued/failed request. A stale processing
// lease is reclaimed after the caller-provided cutoff so a crash cannot leave
// a user suspended forever without deletion progress.
func (r *AccountDeletionRepository) ClaimNext(staleBefore time.Time) (*models.AccountDeletionRequest, error) {
	var request models.AccountDeletionRequest
	err := r.db.Transaction(func(tx *gorm.DB) error {
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status IN ? OR (status = ? AND processing_started_at < ?)", []string{"queued", "failed"}, "processing", staleBefore).
			Order("created_at ASC").
			First(&request).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		now := time.Now().UTC()
		result := tx.Model(&models.AccountDeletionRequest{}).Where("id = ?", request.ID).Updates(map[string]interface{}{
			"status":                "processing",
			"processing_started_at": now,
			"attempt_count":         gorm.Expr("attempt_count + 1"),
			"last_error":            nil,
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}
		request.Status = "processing"
		request.ProcessingStartedAt = &now
		request.AttemptCount++
		request.LastError = nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	if request.ID == [16]byte{} {
		return nil, nil
	}
	return &request, nil
}

func (r *AccountDeletionRepository) MarkProductDataDeleted(id string, now time.Time) error {
	return r.db.Model(&models.AccountDeletionRequest{}).Where("id = ?", id).
		Update("product_data_deleted_at", now).Error
}

func (r *AccountDeletionRepository) MarkIAMUserDeleted(id string, now time.Time) error {
	return r.db.Model(&models.AccountDeletionRequest{}).Where("id = ?", id).
		Update("iam_user_deleted_at", now).Error
}

func (r *AccountDeletionRepository) Complete(id string, now time.Time) error {
	return r.db.Model(&models.AccountDeletionRequest{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":                "completed",
		"completed_at":          now,
		"confirmation_email":    "",
		"last_error":            nil,
		"processing_started_at": nil,
	}).Error
}

func (r *AccountDeletionRepository) Fail(id string, message string) error {
	return r.db.Model(&models.AccountDeletionRequest{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":                "failed",
		"last_error":            message,
		"processing_started_at": nil,
	}).Error
}
func (r *AccountDeletionRepository) Save(request *models.AccountDeletionRequest) error {
	return r.db.Save(request).Error
}

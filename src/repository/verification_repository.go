package repository

import (
	"errors"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/utils"
	"gorm.io/gorm"
)

type VerificationRepository struct {
	db *gorm.DB
}

func NewVerificationRepository(db *gorm.DB) *VerificationRepository {
	return &VerificationRepository{db: db}
}

func (r *VerificationRepository) Create(v *models.EmailVerification) error {
	v.TokenDigest = utils.TokenDigest(v.Token)
	return r.db.Create(v).Error
}

func (r *VerificationRepository) GetByToken(token string) (*models.EmailVerification, error) {
	var v models.EmailVerification
	if err := r.db.Where("token_digest = ? OR token = ?", utils.TokenDigest(token), token).First(&v).Error; err != nil {
		return nil, err
	}
	return &v, nil
}

// ConsumeAndVerifyUser atomically consumes an unexpired verification link and
// marks the linked account verified. The legacy raw token branch is temporary
// migration compatibility for links issued before token_digest existed.
func (r *VerificationRepository) ConsumeAndVerifyUser(token string, now time.Time) (bool, error) {
	consumed := false
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var verification models.EmailVerification
		if err := tx.Where("token_digest = ? OR token = ?", utils.TokenDigest(token), token).
			First(&verification).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}

		result := tx.Model(&models.EmailVerification{}).
			Where("id = ? AND verified_at IS NULL AND expires_at > ?", verification.ID, now).
			Update("verified_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}

		if err := tx.Model(&models.User{}).Where("id = ?", verification.UserID).Updates(map[string]interface{}{
			"email_verified":    true,
			"email_verified_at": now,
		}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", verification.UserID).Delete(&models.EmailVerification{}).Error; err != nil {
			return err
		}
		consumed = true
		return nil
	})
	return consumed, err
}

func (r *VerificationRepository) Update(v *models.EmailVerification) error {
	return r.db.Save(v).Error
}

// DeleteByUserID removes all verification tokens for a user (e.g. after successful verification).
func (r *VerificationRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.EmailVerification{}).Error
}

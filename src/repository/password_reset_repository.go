package repository

import (
	"errors"
	"time"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/utils"
	"gorm.io/gorm"
)

type PasswordResetRepository struct {
	db *gorm.DB
}

func NewPasswordResetRepository(db *gorm.DB) *PasswordResetRepository {
	return &PasswordResetRepository{db: db}
}

func (r *PasswordResetRepository) Create(p *models.PasswordReset) error {
	p.TokenDigest = utils.TokenDigest(p.Token)
	return r.db.Create(p).Error
}

func (r *PasswordResetRepository) GetByToken(token string) (*models.PasswordReset, error) {
	var p models.PasswordReset
	if err := r.db.Where("token_digest = ? OR token = ?", utils.TokenDigest(token), token).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// ConsumeAndResetPassword atomically consumes a reset link, updates the
// password, and revokes all refresh sessions. The raw-token branch only keeps
// previously issued links working while the digest migration rolls out.
func (r *PasswordResetRepository) ConsumeAndResetPassword(
	token string,
	passwordHash string,
	now time.Time,
) (bool, error) {
	consumed := false
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var reset models.PasswordReset
		if err := tx.Where("token_digest = ? OR token = ?", utils.TokenDigest(token), token).
			First(&reset).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}

		result := tx.Model(&models.PasswordReset{}).
			Where("id = ? AND used_at IS NULL AND expires_at > ?", reset.ID, now).
			Update("used_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}

		if err := tx.Model(&models.User{}).Where("id = ?", reset.UserID).
			Update("password", passwordHash).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", reset.UserID).Delete(&models.Token{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", reset.UserID).Delete(&models.PasswordReset{}).Error; err != nil {
			return err
		}
		consumed = true
		return nil
	})
	return consumed, err
}

func (r *PasswordResetRepository) Update(p *models.PasswordReset) error {
	return r.db.Save(p).Error
}

// DeleteByUserID removes all reset tokens for a user (e.g. after successful reset).
func (r *PasswordResetRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.PasswordReset{}).Error
}

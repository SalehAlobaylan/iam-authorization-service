package repository

import (
	"github.com/yourusername/iam-authorization-service/src/models"
	"gorm.io/gorm"
)

type PasswordResetRepository struct {
	db *gorm.DB
}

func NewPasswordResetRepository(db *gorm.DB) *PasswordResetRepository {
	return &PasswordResetRepository{db: db}
}

func (r *PasswordResetRepository) Create(p *models.PasswordReset) error {
	return r.db.Create(p).Error
}

func (r *PasswordResetRepository) GetByToken(token string) (*models.PasswordReset, error) {
	var p models.PasswordReset
	if err := r.db.Where("token = ?", token).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *PasswordResetRepository) Update(p *models.PasswordReset) error {
	return r.db.Save(p).Error
}

// DeleteByUserID removes all reset tokens for a user (e.g. after successful reset).
func (r *PasswordResetRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.PasswordReset{}).Error
}

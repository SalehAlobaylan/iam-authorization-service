package repository

import (
	"github.com/yourusername/iam-authorization-service/src/models"
	"gorm.io/gorm"
)

type VerificationRepository struct {
	db *gorm.DB
}

func NewVerificationRepository(db *gorm.DB) *VerificationRepository {
	return &VerificationRepository{db: db}
}

func (r *VerificationRepository) Create(v *models.EmailVerification) error {
	return r.db.Create(v).Error
}

func (r *VerificationRepository) GetByToken(token string) (*models.EmailVerification, error) {
	var v models.EmailVerification
	if err := r.db.Where("token = ?", token).First(&v).Error; err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *VerificationRepository) Update(v *models.EmailVerification) error {
	return r.db.Save(v).Error
}

// DeleteByUserID removes all verification tokens for a user (e.g. after successful verification).
func (r *VerificationRepository) DeleteByUserID(userID string) error {
	return r.db.Where("user_id = ?", userID).Delete(&models.EmailVerification{}).Error
}

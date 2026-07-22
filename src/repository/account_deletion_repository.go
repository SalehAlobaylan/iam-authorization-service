package repository

import (
	"github.com/yourusername/iam-authorization-service/src/models"
	"gorm.io/gorm"
)

type AccountDeletionRepository struct{ db *gorm.DB }

func NewAccountDeletionRepository(db *gorm.DB) *AccountDeletionRepository {
	return &AccountDeletionRepository{db: db}
}
func (r *AccountDeletionRepository) Create(request *models.AccountDeletionRequest) error {
	return r.db.Create(request).Error
}
func (r *AccountDeletionRepository) GetByUserID(userID string) (*models.AccountDeletionRequest, error) {
	var row models.AccountDeletionRequest
	if err := r.db.Where("user_id = ?", userID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}
func (r *AccountDeletionRepository) Queued() ([]models.AccountDeletionRequest, error) {
	var rows []models.AccountDeletionRequest
	err := r.db.Where("status IN ?", []string{"queued", "failed"}).Order("created_at ASC").Limit(20).Find(&rows).Error
	return rows, err
}
func (r *AccountDeletionRepository) Save(request *models.AccountDeletionRequest) error {
	return r.db.Save(request).Error
}

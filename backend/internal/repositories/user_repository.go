package repositories

import (
	"errors"
	"fmt"

	"task-manager/backend/internal/models"

	"gorm.io/gorm"
)

// UserRepository provides high-level, GORM-backed operations for User entities.
// It centralizes all queries to the users table so that services never build
// raw SQL, which helps avoid SQL injection and keeps data access consistent.
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new UserRepository bound to the given *gorm.DB.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user record.
func (r *UserRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

// GetByEmail retrieves a user by email using a parameterized query.
func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByID retrieves a user by ID using a parameterized query.
func (r *UserRepository) GetByID(id string) (*models.User, error) {
	var user models.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// Update persists changes to an existing user.
func (r *UserRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}

// UpdatePassword updates only the password hash column for a given user.
func (r *UserRepository) UpdatePassword(userID, passwordHash string) error {
	return r.db.Model(&models.User{}).
		Where("id = ?", userID).
		Update("password", passwordHash).Error
}

// Delete removes a user by ID.
func (r *UserRepository) Delete(id string) error {
	return r.db.Delete(&models.User{}, "id = ?", id).Error
}

// GetAll retrieves all users. Intended primarily for admin-style views.
func (r *UserRepository) GetAll() ([]models.User, error) {
	var users []models.User
	if err := r.db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}



package repositories

import (
	"fmt"

	"task-manager/backend/internal/models"

	"gorm.io/gorm"
)

// TaskRepository manages persistence and lookup of Task entities.
type TaskRepository struct {
	db *gorm.DB
}

// NewTaskRepository creates a new TaskRepository bound to the given *gorm.DB.
func NewTaskRepository(db *gorm.DB) *TaskRepository {
	return &TaskRepository{db: db}
}

// Create inserts a new task.
func (r *TaskRepository) Create(task *models.Task) error {
	return r.db.Create(task).Error
}

// GetByID returns a single task by ID, preloading the Owner association.
func (r *TaskRepository) GetByID(id string) (*models.Task, error) {
	var task models.Task
	if err := r.db.Preload("Owner").First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("task not found")
		}
		return nil, err
	}
	return &task, nil
}

// GetAll returns all tasks, optionally filtered by owner ID.
func (r *TaskRepository) GetAll(ownerID string) ([]models.Task, error) {
	var tasks []models.Task
	query := r.db.Preload("Owner")

	if ownerID != "" {
		query = query.Where("owner_id = ?", ownerID)
	}

	if err := query.Order("created_at DESC").Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// GetByOwner returns all tasks for a given owner ID.
func (r *TaskRepository) GetByOwner(ownerID string) ([]models.Task, error) {
	var tasks []models.Task
	if err := r.db.Where("owner_id = ?", ownerID).
		Order("created_at DESC").
		Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// Update persists changes to an existing task.
func (r *TaskRepository) Update(task *models.Task) error {
	return r.db.Save(task).Error
}

// Delete removes a task by ID.
func (r *TaskRepository) Delete(id string) error {
	return r.db.Delete(&models.Task{}, "id = ?", id).Error
}



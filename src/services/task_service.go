package services

import (
	"strings"

	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type TaskService struct {
	taskRepo *repository.TaskRepository
	authz    *AuthzService
}

func NewTaskService(taskRepo *repository.TaskRepository, authz *AuthzService) *TaskService {
	return &TaskService{
		taskRepo: taskRepo,
		authz:    authz,
	}
}

func (s *TaskService) CreateTask(claims *utils.AccessTokenClaims, req models.CreateTaskRequest) (*models.Task, error) {
	if !s.authz.HasPermission(claims, "task", "write") {
		return nil, utils.ForbiddenError("insufficient permission to create task")
	}
	if err := utils.ValidateTaskStatus(req.Status); err != nil {
		return nil, utils.ValidationError(err.Error())
	}
	if err := utils.ValidateTaskPriority(req.Priority); err != nil {
		return nil, utils.ValidationError(err.Error())
	}

	ownerID := claims.UserID
	if strings.TrimSpace(req.OwnerID) != "" {
		if !s.authz.IsAdmin(claims) && req.OwnerID != claims.UserID {
			return nil, utils.ForbiddenError("cannot create tasks for another user")
		}
		ownerID = req.OwnerID
	}

	ownerUUID, err := utils.ParseUUID(ownerID)
	if err != nil {
		return nil, utils.ValidationError("invalid owner_id")
	}

	status := req.Status
	if status == "" {
		status = "pending"
	}
	priority := req.Priority
	if priority == "" {
		priority = "medium"
	}

	task := &models.Task{
		Title:       strings.TrimSpace(req.Title),
		Description: strings.TrimSpace(req.Description),
		Status:      status,
		Priority:    priority,
		OwnerID:     ownerUUID,
		DueDate:     req.DueDate,
	}
	if task.Title == "" {
		return nil, utils.ValidationError("title is required")
	}

	if err := s.taskRepo.Create(task); err != nil {
		return nil, utils.InternalServerError("failed to create task")
	}
	return task, nil
}

func (s *TaskService) UpdateTask(claims *utils.AccessTokenClaims, taskID string, req models.UpdateTaskRequest) (*models.Task, error) {
	if !s.authz.HasPermission(claims, "task", "write") {
		return nil, utils.ForbiddenError("insufficient permission to update task")
	}
	if err := utils.ValidateUUID(taskID); err != nil {
		return nil, utils.ValidationError("invalid task id")
	}

	task, err := s.taskRepo.GetByID(taskID)
	if err != nil {
		return nil, utils.NotFoundError("task not found")
	}
	if !s.authz.CanAccessTask(claims, task.OwnerID.String()) {
		return nil, utils.ForbiddenError("cannot update this task")
	}

	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		if title == "" {
			return nil, utils.ValidationError("title cannot be empty")
		}
		task.Title = title
	}
	if req.Description != nil {
		task.Description = strings.TrimSpace(*req.Description)
	}
	if req.Status != nil {
		if err := utils.ValidateTaskStatus(*req.Status); err != nil {
			return nil, utils.ValidationError(err.Error())
		}
		task.Status = *req.Status
	}
	if req.Priority != nil {
		if err := utils.ValidateTaskPriority(*req.Priority); err != nil {
			return nil, utils.ValidationError(err.Error())
		}
		task.Priority = *req.Priority
	}
	if req.DueDate != nil {
		task.DueDate = req.DueDate
	}

	if err := s.taskRepo.Update(task); err != nil {
		return nil, utils.InternalServerError("failed to update task")
	}
	return task, nil
}

func (s *TaskService) DeleteTask(claims *utils.AccessTokenClaims, taskID string) error {
	if !s.authz.HasPermission(claims, "task", "delete") {
		return utils.ForbiddenError("insufficient permission to delete task")
	}
	if err := utils.ValidateUUID(taskID); err != nil {
		return utils.ValidationError("invalid task id")
	}

	task, err := s.taskRepo.GetByID(taskID)
	if err != nil {
		return utils.NotFoundError("task not found")
	}
	if !s.authz.CanAccessTask(claims, task.OwnerID.String()) {
		return utils.ForbiddenError("cannot delete this task")
	}
	if err := s.taskRepo.Delete(taskID); err != nil {
		return utils.InternalServerError("failed to delete task")
	}
	return nil
}

func (s *TaskService) GetTaskByID(claims *utils.AccessTokenClaims, taskID string) (*models.Task, error) {
	if !s.authz.HasPermission(claims, "task", "read") {
		return nil, utils.ForbiddenError("insufficient permission to view task")
	}
	if err := utils.ValidateUUID(taskID); err != nil {
		return nil, utils.ValidationError("invalid task id")
	}

	task, err := s.taskRepo.GetByID(taskID)
	if err != nil {
		return nil, utils.NotFoundError("task not found")
	}
	if !s.authz.CanAccessTask(claims, task.OwnerID.String()) {
		return nil, utils.ForbiddenError("cannot access this task")
	}
	return task, nil
}

func (s *TaskService) GetTasksByUser(claims *utils.AccessTokenClaims, userID string) ([]models.Task, error) {
	if !s.authz.HasPermission(claims, "task", "read") {
		return nil, utils.ForbiddenError("insufficient permission to view tasks")
	}
	if err := utils.ValidateUUID(userID); err != nil {
		return nil, utils.ValidationError("invalid user id")
	}
	if !s.authz.CanAccessUser(claims, userID) {
		return nil, utils.ForbiddenError("cannot access tasks for this user")
	}
	tasks, err := s.taskRepo.GetByOwner(userID)
	if err != nil {
		return nil, utils.InternalServerError("failed to list tasks")
	}
	return tasks, nil
}

func (s *TaskService) GetTasks(claims *utils.AccessTokenClaims, ownerID string, page, limit int, sortBy, order string) ([]models.Task, int64, error) {
	if !s.authz.HasPermission(claims, "task", "read") {
		return nil, 0, utils.ForbiddenError("insufficient permission to view tasks")
	}

	filterOwner := ownerID
	if !s.authz.IsAdmin(claims) {
		filterOwner = claims.UserID
	}

	tasks, total, err := s.taskRepo.GetWithPagination(filterOwner, page, limit, sortBy, order)
	if err != nil {
		return nil, 0, utils.InternalServerError("failed to list tasks")
	}
	return tasks, total, nil
}

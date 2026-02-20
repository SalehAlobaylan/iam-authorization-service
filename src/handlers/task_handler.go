package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type TaskHandler struct {
	taskService *services.TaskService
}

func NewTaskHandler(taskService *services.TaskService) *TaskHandler {
	return &TaskHandler{taskService: taskService}
}

func (h *TaskHandler) CreateTask(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	var req models.CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}

	task, svcErr := h.taskService.CreateTask(claims, req)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusCreated, task)
}

func (h *TaskHandler) UpdateTask(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	var req models.UpdateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}

	task, svcErr := h.taskService.UpdateTask(claims, c.Param("id"), req)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, task)
}

func (h *TaskHandler) DeleteTask(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	if svcErr := h.taskService.DeleteTask(claims, c.Param("id")); svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TaskHandler) GetTaskByID(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	task, svcErr := h.taskService.GetTaskByID(claims, c.Param("id"))
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, task)
}

func (h *TaskHandler) GetTasksByUser(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	tasks, svcErr := h.taskService.GetTasksByUser(claims, c.Param("user_id"))
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func (h *TaskHandler) GetTasks(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	page := parseIntOrDefault(c.Query("page"), 1)
	limit := parseIntOrDefault(c.Query("limit"), 10)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}
	sortBy := c.DefaultQuery("sort_by", "created_at")
	order := c.DefaultQuery("order", "desc")

	tasks, total, svcErr := h.taskService.GetTasks(claims, c.Query("owner_id"), page, limit, sortBy, order)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tasks": tasks,
		"meta": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

func parseIntOrDefault(value string, defaultValue int) int {
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

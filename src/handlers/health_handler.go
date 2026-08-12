package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type HealthHandler struct {
	db                   *gorm.DB
	accountDeletionReady func() bool
}

func NewHealthHandler(db *gorm.DB, accountDeletionReady func() bool) *HealthHandler {
	return &HealthHandler{db: db, accountDeletionReady: accountDeletionReady}
}

// Health returns the health status of the service
// GET /health
func (h *HealthHandler) Health(c *gin.Context) {
	// Check database connection
	sqlDB, err := h.db.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "unhealthy",
			"message": "database connection error",
		})
		return
	}

	// Ping the database
	if err := sqlDB.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "unhealthy",
			"message": "database ping failed",
		})
		return
	}

	deletionReady := h.accountDeletionReady != nil && h.accountDeletionReady()
	if !deletionReady {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "unhealthy",
			"message": "required IAM migrations are not applied",
			"components": gin.H{
				"database":         "ready",
				"account_deletion": "schema_unavailable",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"message": "IAM Authorization Service is running",
		"components": gin.H{
			"database":         "ready",
			"account_deletion": "ready",
		},
	})
}

// Welcome returns a welcome message with service information
// GET /
func (h *HealthHandler) Welcome(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to IAM Authorization Service",
		"service": "iam-authorization-service",
		"version": "1.0.0",
		"docs": gin.H{
			"health":   "/health",
			"api_base": "/api/v1",
			"auth":     "/api/v1/auth",
			"users":    "/api/v1/users",
			"roles":    "/api/v1/roles",
			"iam":      "/api/v1/iam",
		},
	})
}

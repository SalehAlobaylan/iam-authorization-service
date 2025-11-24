// Admin seeding handler.
//
// This file exposes an administrative endpoint to trigger Go-based database
// seeding (roles, permissions, role-permissions, and default admin role
// assignment). It is intended for development or tightly controlled
// environments only. In production, ensure the route is disabled or
// protected, and wire it conditionally (see main.go and ALLOW_SEED_ENDPOINT).
package handlers

import (
	"net/http"

	dbseed "task-manager/backend/internal/database"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// AdminHandler provides administrative actions such as invoking database seeding.
type AdminHandler struct {
	db *gorm.DB
}

// NewAdminHandler constructs a new AdminHandler backed by the provided *gorm.DB.
func NewAdminHandler(db *gorm.DB) *AdminHandler {
	return &AdminHandler{db: db}
}

// Seed runs the Go-based seeding routine (roles, permissions, role-permissions,
// and assigning the 'admin' role to the default admin user when present).
// Returns 200 OK on success or 500 on failure.
// Important: Protect or disable this route in production.
func (h *AdminHandler) Seed(c *gin.Context) {
	if err := dbseed.Seed(h.db); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "seeding failed", "details": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "seeding completed"})
}

// Admin seeding handler.
//
// This file exposes an administrative endpoint to trigger Go-based database
// seeding (roles, permissions, role-permissions, and default admin role
// assignment). It is intended for development or tightly controlled
// environments only. In production, ensure the route is disabled or
// protected, and wire it conditionally (see main.go and ALLOW_SEED_ENDPOINT).
package handlers

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	migratepkg "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	migrations "github.com/yourusername/iam-authorization-service/database-migrations"
	dbseed "github.com/yourusername/iam-authorization-service/src/database"

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

// MigrateUp applies any pending up-migrations from the embedded files.
// Up-only; rolling back requires a separate destructive endpoint we have
// intentionally not exposed.
func (h *AdminHandler) MigrateUp(c *gin.Context) {
	sqlDB, err := h.db.DB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to obtain database handle",
			"details": err.Error(),
		})
		return
	}

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to init migrate postgres driver",
			"details": err.Error(),
		})
		return
	}

	source, err := iofs.New(migrations.Files, "migrations")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to load embedded migrations",
			"details": err.Error(),
		})
		return
	}

	m, err := migratepkg.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to build migrator",
			"details": err.Error(),
		})
		return
	}

	beforeVersion, beforeDirty, vErr := m.Version()
	beforeApplied := true
	if errors.Is(vErr, migratepkg.ErrNilVersion) {
		beforeApplied = false
	} else if vErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to read current migration version",
			"details": vErr.Error(),
		})
		return
	}

	// nilableVersion returns a *uint that is nil when no migrations have
	// been applied yet — distinguishes "no version" from "version 0".
	nilableVersion := func(applied bool, v uint) *uint {
		if !applied {
			return nil
		}
		return &v
	}

	err = m.Up()
	if err != nil && !errors.Is(err, migratepkg.ErrNoChange) {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":         "Migration failed",
			"details":       err.Error(),
			"start_version": nilableVersion(beforeApplied, beforeVersion),
			"dirty":         beforeDirty,
		})
		return
	}

	afterVersion, afterDirty, avErr := m.Version()
	afterApplied := true
	if errors.Is(avErr, migratepkg.ErrNilVersion) {
		afterApplied = false
	}

	message := "Migrations applied"
	applied := true
	if errors.Is(err, migratepkg.ErrNoChange) {
		message = "Already up to date — no migrations applied"
		applied = false
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         message,
		"applied":         applied,
		"start_version":   nilableVersion(beforeApplied, beforeVersion),
		"current_version": nilableVersion(afterApplied, afterVersion),
		"dirty":           afterDirty,
	})
}

// Restart responds 202 Accepted and exits the process after a brief delay so
// the HTTP response can flush. The process must be supervised (Cranl, k8s,
// systemd) for it to actually come back up; locally it will simply die.
func (h *AdminHandler) Restart(c *gin.Context) {
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Restart accepted. Service is shutting down — supervisor must bring it back.",
		"service": "iam",
	})

	go func() {
		time.Sleep(250 * time.Millisecond)
		log.Println("[IAM] Restart requested via /admin/restart — exiting")
		os.Exit(0)
	}()
}

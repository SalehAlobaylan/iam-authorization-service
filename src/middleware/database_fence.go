package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// DatabaseWriterFence is subtractive: absence preserves compatibility, while a
// sealed canonical fence denies every application mutation.
func DatabaseWriterFence(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/internal/database-migration/") {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			c.Next()
			return
		}
		var exists bool
		if err := db.Raw(`SELECT to_regclass('public.wahb_database_writer_fence') IS NOT NULL`).Scan(&exists).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "database writer authority is unavailable"})
			return
		}
		if !exists {
			c.Next()
			return
		}
		var state string
		var epoch int64
		if err := db.Raw(`SELECT state, epoch FROM wahb_database_writer_fence WHERE singleton = TRUE`).Row().Scan(&state, &epoch); err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "database writer fence is unavailable"})
			return
		}
		if state != "open" && state != "successor_open" {
			c.AbortWithStatusJSON(http.StatusLocked, gin.H{"error": "database writes are fenced", "fence_state": state, "epoch": epoch})
			return
		}
		c.Header("X-Wahb-Database-Epoch", fmt.Sprintf("%d", epoch))
		c.Next()
	}
}

// InstallDatabaseWriterFenceCallbacks covers normal repository/service writes
// that do not traverse the HTTP router, such as deletion workers.
func InstallDatabaseWriterFenceCallbacks(db *gorm.DB) {
	check := func(tx *gorm.DB) {
		var exists bool
		probe := tx.Session(&gorm.Session{NewDB: true, SkipHooks: true})
		if err := probe.Raw(`SELECT to_regclass('public.wahb_database_writer_fence') IS NOT NULL`).Scan(&exists).Error; err != nil {
			tx.AddError(fmt.Errorf("database writer authority is unavailable: %w", err))
			return
		}
		if !exists {
			return
		}
		var state string
		var epoch int64
		if err := probe.Raw(`SELECT state, epoch FROM wahb_database_writer_fence WHERE singleton = TRUE`).Row().Scan(&state, &epoch); err != nil {
			tx.AddError(fmt.Errorf("database writer fence is unavailable: %w", err))
			return
		}
		if state != "open" && state != "successor_open" {
			tx.AddError(fmt.Errorf("database writes are fenced at epoch %d (%s)", epoch, state))
		}
	}
	db.Callback().Create().Before("gorm:create").Register("wahb:database_writer_fence", check)
	db.Callback().Update().Before("gorm:update").Register("wahb:database_writer_fence", check)
	db.Callback().Delete().Before("gorm:delete").Register("wahb:database_writer_fence", check)
}

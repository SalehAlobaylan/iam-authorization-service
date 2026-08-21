package handlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/services"
	"gorm.io/gorm"
)

type DatabaseMigrationHandler struct {
	db       *gorm.DB
	deletion *services.AccountDeletionService
}

func NewDatabaseMigrationHandler(db *gorm.DB, deletion *services.AccountDeletionService) *DatabaseMigrationHandler {
	h := &DatabaseMigrationHandler{db: db, deletion: deletion}
	var state string
	if err := db.Raw(`SELECT state FROM database_migration_owner_control WHERE singleton = TRUE`).Scan(&state).Error; err == nil && state == "quiescing" {
		deletion.Quiesce()
	}
	return h
}

type migrationOwnerRequest struct {
	ProgramID     string `json:"program_id"`
	ExpectedEpoch int64  `json:"expected_epoch"`
}

func (h *DatabaseMigrationHandler) fence() (string, int64, error) {
	var state string
	var epoch int64
	err := h.db.Raw(`SELECT state, epoch FROM wahb_database_writer_fence WHERE singleton = TRUE`).Row().Scan(&state, &epoch)
	return state, epoch, err
}

func (h *DatabaseMigrationHandler) ownerControl() (string, sql.NullString, int64, error) {
	var state string
	var programID sql.NullString
	var epoch int64
	err := h.db.Raw(`SELECT state, migration_program_id::text, fence_epoch FROM database_migration_owner_control WHERE singleton = TRUE`).Row().Scan(&state, &programID, &epoch)
	return state, programID, epoch, err
}
func (h *DatabaseMigrationHandler) GetQuiescence(c *gin.Context) {
	state, epoch, err := h.fence()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"state": "unknown"})
		return
	}
	ownerState, programID, ownerEpoch, ownerErr := h.ownerControl()
	if ownerErr != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"state": "unknown", "reason": "owner_control_unavailable"})
		return
	}
	paused, active := h.deletion.Quiescence()
	verdict := "not_quiesced"
	if paused && active == 0 && state == "sealed" {
		verdict = "quiesced"
	} else if paused {
		verdict = "draining"
	}
	c.JSON(http.StatusOK, gin.H{"state": verdict, "writer_fence": gin.H{"state": state, "epoch": epoch}, "owner_control": gin.H{"state": ownerState, "program_id": programID.String, "fence_epoch": ownerEpoch}, "account_deletion": gin.H{"paused": paused, "active": active}, "observed_at": time.Now().UTC()})
}
func (h *DatabaseMigrationHandler) Quiesce(c *gin.Context) {
	var req migrationOwnerRequest
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.ProgramID) == "" || req.ExpectedEpoch < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "program_id and expected_epoch are required"})
		return
	}
	state, epoch, err := h.fence()
	if err != nil || epoch != req.ExpectedEpoch || (state != "quiescing" && state != "sealed") {
		c.JSON(http.StatusConflict, gin.H{"error": "writer fence precondition changed"})
		return
	}
	sqlDB, dbErr := h.db.DB()
	if dbErr != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	result, dbErr := sqlDB.ExecContext(c, `UPDATE database_migration_owner_control SET state='quiescing', migration_program_id=$1, fence_epoch=$2, changed_at=now(), changed_by='migration-coordinator' WHERE singleton=TRUE AND (state='running' OR (migration_program_id=$1 AND fence_epoch=$2))`, req.ProgramID, req.ExpectedEpoch)
	if dbErr != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "owner control update failed"})
		return
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		c.JSON(http.StatusConflict, gin.H{"error": "owner control belongs to another program"})
		return
	}
	h.deletion.Quiesce()
	h.GetQuiescence(c)
}
func (h *DatabaseMigrationHandler) Resume(c *gin.Context) {
	var req migrationOwnerRequest
	if c.ShouldBindJSON(&req) != nil || strings.TrimSpace(req.ProgramID) == "" || req.ExpectedEpoch < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "program_id and expected_epoch are required"})
		return
	}
	state, epoch, err := h.fence()
	if err != nil || epoch != req.ExpectedEpoch || (state != "open" && state != "successor_open") {
		c.JSON(http.StatusConflict, gin.H{"error": "writer fence does not permit resume"})
		return
	}
	sqlDB, dbErr := h.db.DB()
	if dbErr != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	result, dbErr := sqlDB.ExecContext(c, `UPDATE database_migration_owner_control SET state='running', migration_program_id=NULL, fence_epoch=$2, changed_at=now(), changed_by='migration-coordinator' WHERE singleton=TRUE AND migration_program_id=$1`, req.ProgramID, req.ExpectedEpoch)
	if dbErr != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "owner control update failed"})
		return
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		c.JSON(http.StatusConflict, gin.H{"error": "owner control is not owned by program"})
		return
	}
	h.deletion.Resume()
	h.GetQuiescence(c)
}

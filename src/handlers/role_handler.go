package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type RoleHandler struct {
	authzService *services.AuthzService
}

func NewRoleHandler(authzService *services.AuthzService) *RoleHandler {
	return &RoleHandler{authzService: authzService}
}

func (h *RoleHandler) GetMyAccess(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":      claims.UserID,
		"email":        claims.Email,
		"tenant_id":    claims.TenantID,
		"role":         claims.Role,
		"roles":        claims.Roles,
		"permissions":  claims.Permissions,
		"is_admin":     claims.IsAdmin,
		"token_expiry": claims.ExpiresAt,
	})
}

func (h *RoleHandler) AssignRole(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	if !h.authzService.IsAdmin(claims) {
		respondError(c, utils.ForbiddenError("admin role required"))
		return
	}

	var req models.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}
	if err := utils.ValidateUUID(req.UserID); err != nil {
		respondError(c, utils.ValidationError("invalid user id"))
		return
	}

	if err := h.authzService.AssignRoleToUser(req.UserID, req.RoleName); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "role assigned"})
}

func (h *RoleHandler) GetUserRoles(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	if !h.authzService.IsAdmin(claims) && !h.authzService.HasPermission(claims, "user", "read") {
		respondError(c, utils.ForbiddenError("insufficient permission to view roles"))
		return
	}

	userID := c.Param("user_id")
	if err := utils.ValidateUUID(userID); err != nil {
		respondError(c, utils.ValidationError("invalid user id"))
		return
	}

	roles, svcErr := h.authzService.GetUserRoles(userID)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": roles})
}

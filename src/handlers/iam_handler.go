package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type IAMHandler struct {
	iamService *services.IAMService
	authz      *services.AuthzService
}

func NewIAMHandler(iamService *services.IAMService, authz *services.AuthzService) *IAMHandler {
	return &IAMHandler{
		iamService: iamService,
		authz:      authz,
	}
}

type updateUserRolesRequest struct {
	Roles []string `json:"roles"`
}

type updateUserPermissionsRequest struct {
	Permissions []string `json:"permissions"`
}

func (h *IAMHandler) ListRoles(c *gin.Context) {
	roles, err := h.iamService.ListRoles()
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": roles})
}

func (h *IAMHandler) ListPermissions(c *gin.Context) {
	permissions, err := h.iamService.ListPermissions()
	if err != nil {
		respondError(c, err)
		return
	}

	response := make([]gin.H, 0, len(permissions))
	for _, permission := range permissions {
		response = append(response, gin.H{
			"id":          permission.ID,
			"resource":    permission.Resource,
			"action":      permission.Action,
			"description": permission.Description,
			"key":         permission.Resource + ":" + permission.Action,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": response})
}

func (h *IAMHandler) ListUsers(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	if claims.TenantID == "" {
		respondError(c, utils.ForbiddenError("tenant_id claim is required"))
		return
	}

	users, listErr := h.iamService.ListUsers(claims.TenantID)
	if listErr != nil {
		respondError(c, listErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users})
}

func (h *IAMHandler) GetUserRoles(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	if claims.TenantID == "" {
		respondError(c, utils.ForbiddenError("tenant_id claim is required"))
		return
	}

	roles, svcErr := h.iamService.GetUserRoles(c.Param("user_id"), claims.TenantID)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": roles})
}

func (h *IAMHandler) UpdateUserRoles(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	if claims.TenantID == "" {
		respondError(c, utils.ForbiddenError("tenant_id claim is required"))
		return
	}
	if !h.authz.HasPermission(claims, "iam", "write") && !h.authz.IsAdmin(claims) {
		respondError(c, utils.ForbiddenError("insufficient permission to update roles"))
		return
	}

	var req updateUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}
	if svcErr := h.iamService.UpdateUserRoles(c.Param("user_id"), claims.TenantID, req.Roles); svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "roles updated"})
}

func (h *IAMHandler) UpdateUserPermissions(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	if claims.TenantID == "" {
		respondError(c, utils.ForbiddenError("tenant_id claim is required"))
		return
	}
	if !h.authz.HasPermission(claims, "iam", "write") && !h.authz.IsAdmin(claims) {
		respondError(c, utils.ForbiddenError("insufficient permission to update permissions"))
		return
	}

	var req updateUserPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}

	if svcErr := h.iamService.UpdateUserPermissions(c.Param("user_id"), claims.TenantID, req.Permissions); svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "permissions updated"})
}

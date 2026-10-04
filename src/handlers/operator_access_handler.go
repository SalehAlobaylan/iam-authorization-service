package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type OperatorAccessHandler struct {
	iamService *services.IAMService
}

func NewOperatorAccessHandler(iamService *services.IAMService) *OperatorAccessHandler {
	return &OperatorAccessHandler{iamService: iamService}
}

func (h *OperatorAccessHandler) GetSnapshot(c *gin.Context) {
	userID := c.Param("user_id")
	tenantID := c.Query("tenant_id")
	if userID == "" || tenantID == "" {
		respondError(c, utils.ValidationError("user_id and tenant_id are required"))
		return
	}
	snapshot, err := h.iamService.GetOperatorAccessSnapshot(userID, tenantID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

// GetMySnapshot binds live database roles to the authenticated subject. A
// browser cannot choose the actor, tenant, or machine capability.
func (h *OperatorAccessHandler) GetMySnapshot(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	snapshot, err := h.iamService.GetOperatorAccessSnapshot(claims.UserID, claims.TenantID)
	if err != nil {
		respondError(c, err)
		return
	}
	if !snapshot.Active {
		respondError(c, utils.ForbiddenError("account is inactive"))
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

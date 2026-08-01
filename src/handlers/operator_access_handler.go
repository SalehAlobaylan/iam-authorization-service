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

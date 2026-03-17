package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type PasswordResetHandler struct {
	resetService *services.PasswordResetService
}

func NewPasswordResetHandler(resetService *services.PasswordResetService) *PasswordResetHandler {
	return &PasswordResetHandler{resetService: resetService}
}

// ForgotPassword handles POST /api/v1/auth/forgot-password
func (h *PasswordResetHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("valid email is required"))
		return
	}

	if err := h.resetService.ForgotPassword(req.Email); err != nil {
		respondError(c, err)
		return
	}

	// Always return success to avoid revealing whether the email exists
	c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a password reset link has been sent"})
}

// ResetPassword handles POST /api/v1/auth/reset-password
func (h *PasswordResetHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("token and new_password are required"))
		return
	}

	if err := h.resetService.ResetPassword(req.Token, req.NewPassword); err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password reset successfully"})
}

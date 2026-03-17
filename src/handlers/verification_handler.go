package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type VerificationHandler struct {
	verificationService *services.VerificationService
}

func NewVerificationHandler(verificationService *services.VerificationService) *VerificationHandler {
	return &VerificationHandler{verificationService: verificationService}
}

// VerifyEmail handles POST /api/v1/auth/verify-email
func (h *VerificationHandler) VerifyEmail(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("token is required"))
		return
	}

	if err := h.verificationService.VerifyEmail(req.Token); err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email verified successfully"})
}

// ResendVerification handles POST /api/v1/auth/resend-verification
func (h *VerificationHandler) ResendVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("valid email is required"))
		return
	}

	if err := h.verificationService.ResendVerification(req.Email); err != nil {
		respondError(c, err)
		return
	}

	// Always return success to avoid revealing whether the email exists
	c.JSON(http.StatusOK, gin.H{"message": "if the email exists and is not verified, a verification email has been sent"})
}

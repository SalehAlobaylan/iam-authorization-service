package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/middleware"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}

	// tenant_id is intentionally not taken from the request: public
	// self-registration always lands in the server's default tenant.
	user, err := h.authService.Register(req.Username, req.Email, req.Password, "")
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":                    user.ID,
		"username":              user.Username,
		"email":                 user.Email,
		"tenant_id":             user.TenantID,
		"created_at":            user.CreatedAt,
		"verification_delivery": user.VerificationDelivery,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}

	tokens, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}

	tokens, err := h.authService.Refresh(req.RefreshToken)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}
	if err := h.authService.Logout(req.RefreshToken); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}

func (h *AuthHandler) Reauthenticate(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authenticated identity"})
		return
	}
	var req struct {
		Password     string `json:"password" binding:"required"`
		Purpose      string `json:"purpose" binding:"required"`
		PlanID       string `json:"plan_id" binding:"required"`
		ManifestHash string `json:"manifest_hash" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request payload"))
		return
	}
	proof, err := h.authService.Reauthenticate(claims.UserID, req.Password, req.Purpose, req.PlanID, req.ManifestHash)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"proof": proof, "expires_in": 300})
}

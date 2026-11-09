package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type PasskeyHandler struct {
	service *services.Passkeys
}

func NewPasskeyHandler(service *services.Passkeys) *PasskeyHandler {
	return &PasskeyHandler{service: service}
}

func (h *PasskeyHandler) request(c *gin.Context, destination any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10)
	if err := c.ShouldBindJSON(destination); err != nil {
		respondError(c, utils.ValidationError("invalid passkey request"))
		return false
	}
	return true
}

type passkeyFinish struct {
	Binding    string          `json:"binding" binding:"required,len=43"`
	Credential json.RawMessage `json:"credential" binding:"required"`
}

func (h *PasskeyHandler) BeginAuthentication(c *gin.Context) {
	options, binding, err := h.service.BeginAuthentication(c.Request.Context())
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"options": options, "binding": binding})
}

func (h *PasskeyHandler) FinishAuthentication(c *gin.Context) {
	var req passkeyFinish
	if !h.request(c, &req) {
		return
	}
	tokens, err := h.service.FinishAuthentication(c.Request.Context(), req.Binding, req.Credential)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *PasskeyHandler) BeginRegistration(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	var req struct {
		Password string `json:"password" binding:"required,max=72"`
	}
	if !h.request(c, &req) {
		return
	}
	options, binding, err := h.service.BeginRegistration(c.Request.Context(), claims.UserID, req.Password)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"options": options, "binding": binding})
}

func (h *PasskeyHandler) FinishRegistration(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	var req passkeyFinish
	if !h.request(c, &req) {
		return
	}
	if err := h.service.FinishRegistration(c.Request.Context(), claims.UserID, req.Binding, req.Credential); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *PasskeyHandler) List(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	items, err := h.service.List(c.Request.Context(), claims.UserID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, items)
}

func (h *PasskeyHandler) Remove(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}
	var req struct {
		ID       string `json:"id" binding:"required,max=1400"`
		Password string `json:"password" binding:"required,max=72"`
	}
	if !h.request(c, &req) {
		return
	}
	if err := h.service.Remove(c.Request.Context(), claims.UserID, req.Password, req.ID); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

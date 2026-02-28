package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

type UserHandler struct {
	userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

func (h *UserHandler) GetUserProfile(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	user, svcErr := h.userService.GetProfile(claims, "")
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) GetUserProfileByUserID(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	user, svcErr := h.userService.GetProfile(claims, c.Param("user_id"))
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request body"))
		return
	}

	user, svcErr := h.userService.UpdateProfile(claims, req)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) GetUsers(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	users, svcErr := h.userService.GetUsers(claims)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	if svcErr := h.userService.DeleteUser(claims, c.Param("user_id")); svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.Status(http.StatusNoContent)
}

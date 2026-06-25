package handlers

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/models"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

// maxAvatarBytes caps avatar uploads to keep storage + decode work bounded.
const maxAvatarBytes = 5 << 20 // 5 MiB

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

// UploadAvatar accepts a multipart image (field "avatar"), validates it, stores
// it in object storage, and points the user's avatar_url at the public URL.
func (h *UserHandler) UploadAvatar(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	fileHeader, err := c.FormFile("avatar")
	if err != nil {
		respondError(c, utils.ValidationError("avatar file is required"))
		return
	}
	if fileHeader.Size > maxAvatarBytes {
		respondError(c, utils.ValidationError("avatar must be 5MB or smaller"))
		return
	}

	f, err := fileHeader.Open()
	if err != nil {
		respondError(c, utils.ValidationError("could not read avatar file"))
		return
	}
	defer f.Close()

	// Read at most maxAvatarBytes+1 so an oversized stream is caught even if the
	// declared header size lied.
	data, err := io.ReadAll(io.LimitReader(f, maxAvatarBytes+1))
	if err != nil {
		respondError(c, utils.InternalServerError("could not read avatar file"))
		return
	}
	if int64(len(data)) > maxAvatarBytes {
		respondError(c, utils.ValidationError("avatar must be 5MB or smaller"))
		return
	}

	contentType := http.DetectContentType(data)
	ext, ok := avatarExtFor(contentType)
	if !ok {
		respondError(c, utils.ValidationError("avatar must be a PNG, JPEG, or WebP image"))
		return
	}

	user, svcErr := h.userService.UploadAvatar(claims, data, contentType, ext)
	if svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, user)
}

// avatarExtFor maps a sniffed image content-type to a file extension, rejecting
// anything that is not a supported avatar image.
func avatarExtFor(contentType string) (string, bool) {
	switch contentType {
	case "image/jpeg":
		return ".jpg", true
	case "image/png":
		return ".png", true
	case "image/webp":
		return ".webp", true
	default:
		return "", false
	}
}

// ChangePasswordRequest carries the JSON payload for self-service password change.
type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	claims, err := claimsFromContext(c)
	if err != nil {
		respondError(c, utils.UnauthorizedError("missing auth context"))
		return
	}

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, utils.ValidationError("invalid request body"))
		return
	}

	if svcErr := h.userService.ChangePassword(claims, req.CurrentPassword, req.NewPassword); svcErr != nil {
		respondError(c, svcErr)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
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

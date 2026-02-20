package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/middleware"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

func respondError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	if apiErr, ok := utils.AsAPIError(err); ok {
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.Message})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}

func claimsFromContext(c *gin.Context) (*utils.AccessTokenClaims, error) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		return nil, errors.New("missing auth claims in context")
	}
	return claims, nil
}

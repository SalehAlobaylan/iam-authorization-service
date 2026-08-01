package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireServiceToken authenticates a narrowly scoped service-to-service
// endpoint. An unset token fails closed rather than accidentally accepting an
// empty Authorization header in a partial deployment.
func RequireServiceToken(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		expected = strings.TrimSpace(expected)
		if expected == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "service capability is not configured"})
			return
		}
		header := strings.TrimSpace(c.GetHeader("Authorization"))
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(parts[1])), []byte(expected)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid service authorization"})
			return
		}
		c.Next()
	}
}

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/repository"
)

// RejectSuspendedUser is placed after JWT validation on every protected IAM
// route. This prevents a token minted before suspension from continuing to
// access IAM while CMS independently rejects it through its enforcement mirror.
func RejectSuspendedUser(users *repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth claims"})
			return
		}
		user, err := users.GetByID(claims.UserID)
		if err != nil || user.SuspendedAt != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account suspended"})
			return
		}
		c.Next()
	}
}

package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth claims"})
			return
		}
		if claims.IsAdmin {
			c.Next()
			return
		}

		for _, candidate := range claims.Roles {
			if candidate == role {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
	}
}

func RequirePermission(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth claims"})
			return
		}
		if claims.IsAdmin {
			c.Next()
			return
		}

		for _, permission := range claims.Permissions {
			if permission.Resource != resource {
				continue
			}
			for _, allowedAction := range permission.Actions {
				if allowedAction == action {
					c.Next()
					return
				}
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permission"})
	}
}

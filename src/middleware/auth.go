package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

const claimsContextKey = "access_claims"

func Authenticate(secret string) gin.HandlerFunc {
	return AuthenticateWithClaims(secret, "", "")
}

func AuthenticateWithClaims(secret, expectedIssuer, expectedAudience string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			return
		}

		claims, err := utils.ValidateAccessToken(parts[1], secret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired access token"})
			return
		}
		if expectedIssuer != "" && !strings.EqualFold(claims.Issuer, expectedIssuer) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token issuer"})
			return
		}
		if expectedAudience != "" {
			audienceMatched := false
			for _, audience := range claims.Audience {
				if strings.EqualFold(audience, expectedAudience) {
					audienceMatched = true
					break
				}
			}
			if !audienceMatched {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token audience"})
				return
			}
		}

		c.Set(claimsContextKey, claims)
		c.Next()
	}
}

func GetClaims(c *gin.Context) (*utils.AccessTokenClaims, bool) {
	value, ok := c.Get(claimsContextKey)
	if !ok {
		return nil, false
	}
	claims, ok := value.(*utils.AccessTokenClaims)
	return claims, ok
}

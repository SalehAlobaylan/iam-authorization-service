package routes

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/middleware"
	"os"
	"strings"
	"time"
)

func setupMiddleware(router *gin.Engine) {
	router.Use(gin.Recovery())
	router.Use(middleware.RequestLogger())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     getAllowedOrigins(),
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
}

func getAllowedOrigins() []string {
	allowed := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if allowed == "" {
		return []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:3005",
			"http://127.0.0.1:3005",
			"http://host.docker.internal",
			"https://wahb-console.vercel.app",
		}
	}

	parts := strings.Split(allowed, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		origins = append(origins, origin)
	}
	if len(origins) == 0 {
		return []string{"https://wahb-console.vercel.app"}
	}
	return origins
}

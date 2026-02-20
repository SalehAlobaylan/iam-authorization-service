package routes

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/middleware"
)

func setupRoutes(router *gin.Engine, h *Handlers, _ *Services, cfg *config.Config) {
	v1 := router.Group("/api/v1")

	auth := v1.Group("/auth")
	auth.POST("/register", h.Auth.Register)
	auth.POST("/login", h.Auth.Login)
	auth.POST("/refresh", h.Auth.Refresh)

	protected := v1.Group("")
	protected.Use(middleware.AuthenticateWithClaims(cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Audience))
	protected.POST("/auth/logout", h.Auth.Logout)

	tasks := protected.Group("/tasks")
	tasks.POST("", middleware.RequirePermission("task", "write"), h.Task.CreateTask)
	tasks.PUT("/:id", middleware.RequirePermission("task", "write"), h.Task.UpdateTask)
	tasks.DELETE("/:id", middleware.RequirePermission("task", "delete"), h.Task.DeleteTask)
	tasks.GET("/:id", middleware.RequirePermission("task", "read"), h.Task.GetTaskByID)
	tasks.GET("", middleware.RequirePermission("task", "read"), h.Task.GetTasks)

	users := protected.Group("/users")
	users.GET("", middleware.RequirePermission("user", "read"), h.User.GetUsers)
	users.DELETE("/:user_id", middleware.RequirePermission("user", "delete"), h.User.DeleteUser)
	users.GET("/:user_id/tasks", middleware.RequirePermission("task", "read"), h.Task.GetTasksByUser)
	users.GET("/profile", middleware.RequirePermission("profile", "read"), h.User.GetUserProfile)
	users.GET("/profile/:user_id", middleware.RequirePermission("profile", "read"), h.User.GetUserProfileByUserID)

	roles := protected.Group("/roles")
	roles.GET("/me", h.Role.GetMyAccess)
	roles.POST("/assign", middleware.RequireRole("admin"), h.Role.AssignRole)
	roles.GET("/users/:user_id", middleware.RequirePermission("user", "read"), h.Role.GetUserRoles)

	iam := protected.Group("/iam")
	iam.Use(middleware.RequirePermission("iam", "read"))
	iam.GET("/roles", h.IAM.ListRoles)
	iam.GET("/permissions", h.IAM.ListPermissions)
	iam.GET("/users", h.IAM.ListUsers)
	iam.GET("/users/:user_id/roles", h.IAM.GetUserRoles)
	iam.PUT("/users/:user_id/roles", middleware.RequirePermission("iam", "write"), h.IAM.UpdateUserRoles)
	iam.PUT("/users/:user_id/permissions", middleware.RequirePermission("iam", "write"), h.IAM.UpdateUserPermissions)

	if os.Getenv("ALLOW_SEED_ENDPOINT") == "true" {
		admin := protected.Group("/admin")
		admin.POST("/seed", middleware.RequireRole("admin"), h.Admin.Seed)
	}
}

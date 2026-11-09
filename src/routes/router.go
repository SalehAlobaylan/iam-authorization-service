package routes

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/middleware"
)

func setupRoutes(router *gin.Engine, h *Handlers, repos *Repositories, svcs *Services, cfg *config.Config) {
	// Public endpoints - no authentication required
	router.GET("/", h.Health.Welcome)
	router.GET("/health", h.Health.Health)

	v1 := router.Group("/api/v1")

	auth := v1.Group("/auth")
	auth.POST("/register", h.Auth.Register)
	auth.POST("/login", h.Auth.Login)
	auth.POST("/refresh", h.Auth.Refresh)
	auth.POST("/revoke-session", h.Auth.RevokeSession)
	auth.POST("/verify-email", h.Verification.VerifyEmail)
	auth.POST("/resend-verification", h.Verification.ResendVerification)
	auth.POST("/forgot-password", h.PasswordReset.ForgotPassword)
	auth.POST("/reset-password", h.PasswordReset.ResetPassword)
	auth.GET("/console-capabilities", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{
			"origin": cfg.ConsoleAuth.Origin, "recovery": cfg.ConsoleAuth.Recovery, "passkeys": h.Passkeys != nil,
		})
	})
	if h.Passkeys != nil {
		auth.POST("/passkeys/authentication/begin", h.Passkeys.BeginAuthentication)
		auth.POST("/passkeys/authentication/finish", h.Passkeys.FinishAuthentication)
	}

	protected := v1.Group("")
	protected.Use(middleware.AuthenticateWithClaims(cfg.JWT.Secret, cfg.JWT.Issuer, cfg.JWT.Audience))
	protected.Use(middleware.RejectSuspendedUser(repos.User))
	protected.POST("/auth/logout", h.Auth.Logout)
	if h.Passkeys != nil {
		protected.GET("/auth/passkeys", h.Passkeys.List)
		protected.POST("/auth/passkeys/registration/begin", h.Passkeys.BeginRegistration)
		protected.POST("/auth/passkeys/registration/finish", h.Passkeys.FinishRegistration)
		protected.POST("/auth/passkeys/remove", h.Passkeys.Remove)
	}
	protected.POST("/auth/reauth", middleware.RequireRole("admin"), h.Auth.Reauthenticate)

	// CMS alone calls this capability to refresh durable Operator authority.
	// It deliberately sits outside human JWT routes and exposes no mutation.
	operatorInternal := router.Group("/internal/access")
	operatorInternal.Use(middleware.RequireServiceToken(cfg.Operator.AccessSnapshotToken))
	operatorInternal.GET("/users/:user_id", h.OperatorAccess.GetSnapshot)
	operatorInternal.GET("/economics/erasures", func(c *gin.Context) {
		after := time.Unix(0, 0).UTC()
		if raw := c.Query("after"); raw != "" {
			parsed, e := time.Parse(time.RFC3339Nano, raw)
			if e != nil {
				c.JSON(400, gin.H{"error": "Invalid cursor"})
				return
			}
			after = parsed
		}
		user := c.DefaultQuery("user_id", "00000000-0000-0000-0000-000000000000")
		if _, e := uuid.FromString(user); e != nil {
			c.JSON(400, gin.H{"error": "Invalid cursor"})
			return
		}
		rows, e := repos.Deletion.EconomicsErasureBarriers(after, user)
		if e != nil {
			c.JSON(503, gin.H{"error": "Erasure authority unavailable"})
			return
		}
		more := len(rows) > 100
		if more {
			rows = rows[:100]
		}
		out := []gin.H{}
		for _, r := range rows {
			out = append(out, gin.H{"user_id": r.UserID, "tenant_id": r.TenantID, "erased_at": r.CreatedAt})
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, gin.H{"erasures": out, "has_more": more})
	})

	migrationInternal := router.Group("/internal/database-migration")
	migrationInternal.Use(middleware.RequireServiceToken(os.Getenv("IAM_MIGRATION_COORDINATOR_SERVICE_TOKEN")))
	migrationInternal.GET("/quiescence", h.DatabaseMigration.GetQuiescence)
	migrationInternal.POST("/quiesce", h.DatabaseMigration.Quiesce)
	migrationInternal.POST("/resume", h.DatabaseMigration.Resume)

	users := protected.Group("/users")
	users.GET("", middleware.RequirePermission("user", "read"), h.User.GetUsers)
	users.DELETE("/:user_id", middleware.RequirePermission("user", "delete"), h.User.DeleteUser)
	users.GET("/profile", middleware.RequirePermission("profile", "read"), h.User.GetUserProfile)
	users.PUT("/profile", middleware.RequirePermission("profile", "write"), h.User.UpdateProfile)
	users.POST("/avatar", middleware.RequirePermission("profile", "write"), h.User.UploadAvatar)
	users.PUT("/profile/password", middleware.RequirePermission("profile", "write"), h.User.ChangePassword)
	users.POST("/profile/deletion", middleware.RequirePermission("profile", "write"), h.User.RequestAccountDeletion)
	users.GET("/profile/:user_id", middleware.RequirePermission("profile", "read"), h.User.GetUserProfileByUserID)

	roles := protected.Group("/roles")
	roles.GET("/me", h.Role.GetMyAccess)
	roles.GET("/live", h.OperatorAccess.GetMySnapshot)
	roles.POST("/assign", middleware.RequireRole("admin"), h.Role.AssignRole)
	roles.GET("/users/:user_id", middleware.RequirePermission("user", "read"), h.Role.GetUserRoles)

	iam := protected.Group("/iam")
	iam.Use(middleware.RequirePermission("iam", "read"))
	iam.GET("/roles", h.IAM.ListRoles)
	iam.GET("/permissions", h.IAM.ListPermissions)
	iam.GET("/users", h.IAM.ListUsers)
	iam.GET("/economics-directory", middleware.RequireRole("admin"), h.User.EconomicsDirectory)
	iam.GET("/users/:user_id/roles", h.IAM.GetUserRoles)
	iam.PUT("/users/:user_id/roles", middleware.RequirePermission("iam", "write"), h.IAM.UpdateUserRoles)
	iam.PUT("/users/:user_id/permissions", middleware.RequirePermission("iam", "write"), h.IAM.UpdateUserPermissions)
	iam.PUT("/users/:user_id/suspension", middleware.RequirePermission("iam", "write"), h.IAM.UpdateUserSuspension)

	// Operational endpoints that restart the process or mutate the schema.
	// These are needed by the deploy workflow and are gated by the "admin" role.
	admin := protected.Group("/admin")
	admin.POST("/restart", middleware.RequireRole("admin"), h.Admin.Restart)
	admin.POST("/migrations/up", middleware.RequireRole("admin"), h.Admin.MigrateUp)

	if os.Getenv("ALLOW_SEED_ENDPOINT") == "true" {
		admin.POST("/seed", middleware.RequireRole("admin"), h.Admin.Seed)
	}
}

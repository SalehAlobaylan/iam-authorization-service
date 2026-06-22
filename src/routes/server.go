package routes

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/handlers"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/services"
	"gorm.io/gorm"
)

type Server struct {
	config *config.Config
	router *gin.Engine
	db     *gorm.DB
}

func NewServer(cfg *config.Config, db *gorm.DB) *Server {
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	server := &Server{
		config: cfg,
		router: gin.New(),
		db:     db,
	}

	setupMiddleware(server.router)
	repos := initRepositories(db)
	svcs := initServices(repos, cfg)
	handlers := initHandlers(svcs, db)
	setupRoutes(server.router, handlers, svcs, cfg)

	return server
}

func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%s", s.config.Server.Host, s.config.Server.Port)
	if s.config.Server.Host == "" {
		addr = ":" + s.config.Server.Port
	}
	log.Printf("server starting on %s", addr)
	return s.router.Run(addr)
}

type Repositories struct {
	User          *repository.UserRepository
	Token         *repository.TokenRepository
	Role          *repository.RoleRepository
	Permission    *repository.PermissionRepository
	Verification  *repository.VerificationRepository
	PasswordReset *repository.PasswordResetRepository
}

func initRepositories(db *gorm.DB) *Repositories {
	return &Repositories{
		User:          repository.NewUserRepository(db),
		Token:         repository.NewTokenRepository(db),
		Role:          repository.NewRoleRepository(db),
		Permission:    repository.NewPermissionRepository(db),
		Verification:  repository.NewVerificationRepository(db),
		PasswordReset: repository.NewPasswordResetRepository(db),
	}
}

type Services struct {
	Auth          *services.AuthService
	IAM           *services.IAMService
	Authz         *services.AuthzService
	User          *services.UserService
	Verification  *services.VerificationService
	PasswordReset *services.PasswordResetService
}

func initServices(repos *Repositories, cfg *config.Config) *Services {
	authzSvc := services.NewAuthzService(repos.Role, repos.Permission)

	var emailSender services.EmailSender
	if cfg.Email.SMTPHost != "" {
		emailSender = services.NewSMTPEmailSender(cfg.Email)
	} else {
		emailSender = services.NewLogEmailSender()
	}

	authSvc := services.NewAuthService(repos.User, repos.Token, repos.Role, repos.Permission, cfg)
	verifySvc := services.NewVerificationService(repos.Verification, repos.User, emailSender, cfg)

	// Wire verification into auth so registration triggers email verification
	authSvc.SetVerificationService(verifySvc)

	return &Services{
		Auth:          authSvc,
		IAM:           services.NewIAMService(repos.User, repos.Role, repos.Permission),
		Authz:         authzSvc,
		User:          services.NewUserService(repos.User, repos.Token, authzSvc),
		Verification:  verifySvc,
		PasswordReset: services.NewPasswordResetService(repos.PasswordReset, repos.User, repos.Token, emailSender, cfg),
	}
}

type Handlers struct {
	Auth          *handlers.AuthHandler
	IAM           *handlers.IAMHandler
	User          *handlers.UserHandler
	Role          *handlers.RoleHandler
	Admin         *handlers.AdminHandler
	Health        *handlers.HealthHandler
	Verification  *handlers.VerificationHandler
	PasswordReset *handlers.PasswordResetHandler
}

func initHandlers(svcs *Services, db *gorm.DB) *Handlers {
	return &Handlers{
		Auth:          handlers.NewAuthHandler(svcs.Auth),
		IAM:           handlers.NewIAMHandler(svcs.IAM, svcs.Authz),
		User:          handlers.NewUserHandler(svcs.User),
		Role:          handlers.NewRoleHandler(svcs.Authz),
		Admin:         handlers.NewAdminHandler(db),
		Health:        handlers.NewHealthHandler(db),
		Verification:  handlers.NewVerificationHandler(svcs.Verification),
		PasswordReset: handlers.NewPasswordResetHandler(svcs.PasswordReset),
	}
}

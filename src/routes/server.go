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
	User       *repository.UserRepository
	Token      *repository.TokenRepository
	Role       *repository.RoleRepository
	Permission *repository.PermissionRepository
	Task       *repository.TaskRepository
}

func initRepositories(db *gorm.DB) *Repositories {
	return &Repositories{
		User:       repository.NewUserRepository(db),
		Token:      repository.NewTokenRepository(db),
		Role:       repository.NewRoleRepository(db),
		Permission: repository.NewPermissionRepository(db),
		Task:       repository.NewTaskRepository(db),
	}
}

type Services struct {
	Auth  *services.AuthService
	IAM   *services.IAMService
	Authz *services.AuthzService
	Task  *services.TaskService
	User  *services.UserService
}

func initServices(repos *Repositories, cfg *config.Config) *Services {
	authzSvc := services.NewAuthzService(repos.Role, repos.Permission)
	return &Services{
		Auth:  services.NewAuthService(repos.User, repos.Token, repos.Role, repos.Permission, cfg),
		IAM:   services.NewIAMService(repos.User, repos.Role, repos.Permission),
		Authz: authzSvc,
		Task:  services.NewTaskService(repos.Task, authzSvc),
		User:  services.NewUserService(repos.User, authzSvc),
	}
}

type Handlers struct {
	Auth  *handlers.AuthHandler
	IAM   *handlers.IAMHandler
	Task  *handlers.TaskHandler
	User  *handlers.UserHandler
	Role  *handlers.RoleHandler
	Admin *handlers.AdminHandler
}

func initHandlers(svcs *Services, db *gorm.DB) *Handlers {
	return &Handlers{
		Auth:  handlers.NewAuthHandler(svcs.Auth),
		IAM:   handlers.NewIAMHandler(svcs.IAM, svcs.Authz),
		Task:  handlers.NewTaskHandler(svcs.Task),
		User:  handlers.NewUserHandler(svcs.User),
		Role:  handlers.NewRoleHandler(svcs.Authz),
		Admin: handlers.NewAdminHandler(db),
	}
}

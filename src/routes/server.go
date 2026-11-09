package routes

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/handlers"
	"github.com/yourusername/iam-authorization-service/src/middleware"
	"github.com/yourusername/iam-authorization-service/src/repository"
	"github.com/yourusername/iam-authorization-service/src/services"
	"github.com/yourusername/iam-authorization-service/src/storage"
	"gorm.io/gorm"
)

type Server struct {
	config    *config.Config
	router    *gin.Engine
	db        *gorm.DB
	economics *middleware.EconomicsCounter
}

func NewServer(cfg *config.Config, db *gorm.DB) *Server {
	env := strings.ToLower(strings.TrimSpace(cfg.Env))
	if env != "" && env != "development" && env != "dev" && env != "test" {
		gin.SetMode(gin.ReleaseMode)
	}

	server := &Server{
		config: cfg,
		router: gin.New(),
		db:     db,
	}

	setupMiddleware(server.router)
	economics := middleware.NewEconomicsCounter(cfg.CMS, cfg.Tenancy.DefaultTenantID)
	server.router.Use(economics.Middleware())
	server.economics = economics
	middleware.InstallDatabaseWriterFenceCallbacks(db)
	server.router.Use(middleware.DatabaseWriterFence(db))
	configureTrustedProxies(server.router)
	repos := initRepositories(db)
	svcs := initServices(repos, cfg)
	endpoints := initHandlers(svcs, db, cfg)
	if cfg.ConsoleAuth.Passkeys {
		passkeys, err := services.NewPasskeys(db, svcs.Auth, cfg.ConsoleAuth.Origin)
		if err != nil {
			log.Printf("Console passkeys disabled: %v", err)
		} else {
			endpoints.Passkeys = handlers.NewPasskeyHandler(passkeys)
		}
	}
	setupRoutes(server.router, endpoints, repos, svcs, cfg)

	return server
}

func configureTrustedProxies(router *gin.Engine) {
	raw := strings.TrimSpace(os.Getenv("IAM_TRUSTED_PROXIES"))
	if raw == "" {
		raw = "127.0.0.1,::1"
	}

	parts := strings.Split(raw, ",")
	proxies := make([]string, 0, len(parts))
	for _, part := range parts {
		proxy := strings.TrimSpace(part)
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}

	if len(proxies) == 0 {
		proxies = []string{"127.0.0.1", "::1"}
	}

	if err := router.SetTrustedProxies(proxies); err != nil {
		log.Printf("failed to configure IAM trusted proxies: %v", err)
	}
}

func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%s", s.config.Server.Host, s.config.Server.Port)
	if s.config.Server.Host == "" {
		addr = ":" + s.config.Server.Port
	}
	log.Printf("server starting on %s", addr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	counterContext, stopCounters := context.WithCancel(context.Background())
	defer stopCounters()
	go s.economics.Run(counterContext)
	httpServer := &http.Server{Addr: addr, Handler: s.router, ReadHeaderTimeout: 10 * time.Second}
	finished := make(chan error, 1)
	go func() { finished <- httpServer.ListenAndServe() }()
	select {
	case err := <-finished:
		stop()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(drain)
		s.economics.Close(drain)
	}
	return nil
}

type Repositories struct {
	User          *repository.UserRepository
	Token         *repository.TokenRepository
	Role          *repository.RoleRepository
	Permission    *repository.PermissionRepository
	Verification  *repository.VerificationRepository
	PasswordReset *repository.PasswordResetRepository
	Deletion      *repository.AccountDeletionRepository
}

func initRepositories(db *gorm.DB) *Repositories {
	return &Repositories{
		User:          repository.NewUserRepository(db),
		Token:         repository.NewTokenRepository(db),
		Role:          repository.NewRoleRepository(db),
		Permission:    repository.NewPermissionRepository(db),
		Verification:  repository.NewVerificationRepository(db),
		PasswordReset: repository.NewPasswordResetRepository(db),
		Deletion:      repository.NewAccountDeletionRepository(db),
	}
}

type Services struct {
	Auth          *services.AuthService
	IAM           *services.IAMService
	Authz         *services.AuthzService
	User          *services.UserService
	Verification  *services.VerificationService
	PasswordReset *services.PasswordResetService
	Deletion      *services.AccountDeletionService
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

	// Avatar object-storage is optional: a nil store disables avatar upload but
	// lets IAM boot without MinIO/S3 configured.
	avatarStore, storageErr := storage.NewAvatarStore(storage.Settings{
		Endpoint:  cfg.Storage.Endpoint,
		Region:    cfg.Storage.Region,
		AccessKey: cfg.Storage.AccessKey,
		SecretKey: cfg.Storage.SecretKey,
		Bucket:    cfg.Storage.Bucket,
		PublicURL: cfg.Storage.PublicURL,
	})
	if storageErr != nil {
		log.Printf("avatar storage disabled: %v", storageErr)
		avatarStore = nil
	}

	deletionSvc := services.NewAccountDeletionService(repos.User, repos.Token, repos.Deletion, services.NewCMSSuspensionClient(cfg.CMS), emailSender)
	deletionSvc.Start()
	return &Services{
		Auth:          authSvc,
		IAM:           services.NewIAMService(repos.User, repos.Token, repos.Role, repos.Permission, services.NewCMSSuspensionClient(cfg.CMS)),
		Authz:         authzSvc,
		User:          services.NewUserService(repos.User, repos.Token, authzSvc, avatarStore),
		Verification:  verifySvc,
		PasswordReset: services.NewPasswordResetService(repos.PasswordReset, repos.User, repos.Token, emailSender, cfg),
		Deletion:      deletionSvc,
	}
}

type Handlers struct {
	Passkeys          *handlers.PasskeyHandler
	Auth              *handlers.AuthHandler
	IAM               *handlers.IAMHandler
	User              *handlers.UserHandler
	Role              *handlers.RoleHandler
	Admin             *handlers.AdminHandler
	Health            *handlers.HealthHandler
	Verification      *handlers.VerificationHandler
	PasswordReset     *handlers.PasswordResetHandler
	OperatorAccess    *handlers.OperatorAccessHandler
	DatabaseMigration *handlers.DatabaseMigrationHandler
}

func initHandlers(svcs *Services, db *gorm.DB, cfg *config.Config) *Handlers {
	return &Handlers{
		Auth:              handlers.NewAuthHandler(svcs.Auth),
		IAM:               handlers.NewIAMHandler(svcs.IAM, svcs.Authz),
		User:              handlers.NewUserHandler(svcs.User, svcs.Deletion),
		Role:              handlers.NewRoleHandler(svcs.Authz),
		Admin:             handlers.NewAdminHandler(db),
		Health:            handlers.NewHealthHandler(db, svcs.Deletion.Ready),
		Verification:      handlers.NewVerificationHandler(svcs.Verification),
		PasswordReset:     handlers.NewPasswordResetHandler(svcs.PasswordReset, cfg.ConsoleAuth.Recovery),
		OperatorAccess:    handlers.NewOperatorAccessHandler(svcs.IAM),
		DatabaseMigration: handlers.NewDatabaseMigrationHandler(db, svcs.Deletion),
	}
}

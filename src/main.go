package main

import (
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/database"
	"github.com/yourusername/iam-authorization-service/src/routes"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	logIAMConnectionTargets(cfg)

	db, err := database.NewPostgres(cfg.Database)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}

	if os.Getenv("SEED_ON_STARTUP") == "true" {
		if err := database.Seed(db); err != nil {
			log.Printf("database seed failed: %v", err)
		} else {
			log.Println("database seed completed")
		}
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("failed to get database instance: %v", err)
	}
	defer sqlDB.Close()

	server := routes.NewServer(cfg, db)
	if err := server.Run(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func logIAMConnectionTargets(cfg *config.Config) {
	corsAllowed := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if corsAllowed == "" {
		corsAllowed = "(default allowlist)"
	}

	log.Println("[IAM] Connection targets")
	log.Printf("[IAM] - Server: %s:%s", cfg.Server.Host, cfg.Server.Port)
	log.Printf("[IAM] - Database: %s", iamDatabaseTarget(cfg.Database))
	log.Printf("[IAM] - JWT issuer/audience: %s / %s", cfg.JWT.Issuer, cfg.JWT.Audience)
	log.Printf("[IAM] - CORS allowed origins: %s", corsAllowed)
}

func iamDatabaseTarget(dbCfg config.DatabaseConfig) string {
	if strings.TrimSpace(dbCfg.URL) != "" {
		if parsed, err := url.Parse(dbCfg.URL); err == nil {
			host := parsed.Host
			dbName := strings.TrimPrefix(parsed.Path, "/")
			if dbName == "" {
				dbName = "(default)"
			}
			return host + "/" + dbName
		}
	}

	host := strings.TrimSpace(dbCfg.Host)
	port := strings.TrimSpace(dbCfg.Port)
	dbName := strings.TrimSpace(dbCfg.DBName)
	if dbName == "" {
		dbName = "(default)"
	}
	if host == "" {
		host = "(unknown-host)"
	}
	if port != "" {
		return host + ":" + port + "/" + dbName
	}
	return host + "/" + dbName
}

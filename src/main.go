package main

import (
	"log"
	"os"

	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/database"
	"github.com/yourusername/iam-authorization-service/src/routes"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

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

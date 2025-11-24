package main

import (
	"log"
	"os"
	"task-manager/backend/internal/handlers"
	"task-manager/backend/internal/repositories"
	"time"

	dbseed "task-manager/backend/internal/database"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {

	dbCfg := repositories.NewDatabaseConfig()
	db, err := dbCfg.Connect()
	if err != nil {
		log.Fatal("Database connection failed: ", err)
	}

	// Optional: seed default data on startup when explicitly enabled
	if os.Getenv("SEED_ON_STARTUP") == "true" {
		if err := dbseed.Seed(db); err != nil {
			log.Println("Database seed failed:", err)
		} else {
			log.Println("Database seed completed")
		}
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("Failed to get database instance: ", err)
	}
	defer sqlDB.Close()

	authHandler := handlers.NewAuthHandler(db, nil)

	taskHandler := handlers.NewTaskHandler(db, nil)

	refreshHandler := handlers.NewRefreshHandler(db, nil)

	userHandler := handlers.NewUserHandler(db, nil)

	registrationHandler :=
		handlers.NewRegisterHandler(db, nil)
  	// for seeding the database
	var adminHandler *handlers.AdminHandler
	if os.Getenv("ALLOW_SEED_ENDPOINT") == "true" {
		adminHandler = handlers.NewAdminHandler(db)
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://host.docker.internal"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	v1 := r.Group("/api/v1")
	{
		authRoutes := v1.Group("/auth")
		{
			authRoutes.POST("/register", registrationHandler.Registration)
			authRoutes.POST("/login", authHandler.Token)
			authRoutes.POST("/refresh", refreshHandler.Refresh)
		}
		taskRoutes := v1.Group("/tasks")
		{
			taskRoutes.POST("", taskHandler.CreateTask)
			taskRoutes.PUT("/:id", taskHandler.UpdateTask)
			taskRoutes.DELETE("/:id", taskHandler.DeleteTask)
			taskRoutes.GET("/:id", taskHandler.GetTaskByID)
			taskRoutes.GET("", taskHandler.GetTasks)
		}
		userRoutes := v1.Group("/users")
		{
			userRoutes.DELETE("/:user_id", userHandler.DeleteUser)
			userRoutes.GET("", userHandler.GetUsers)
			userRoutes.GET("/:user_id/tasks", taskHandler.GetTasksByUser)
			userRoutes.GET("/profile", userHandler.GetUserProfile)
			userRoutes.GET("/profile/:user_id", userHandler.GetUserProfileByUserId)
		}
		// for seeding the database
		if adminHandler != nil {
			adminRoutes := v1.Group("/admin")
			{
				adminRoutes.POST("/seed", adminHandler.Seed)
			}
		}
	}
	r.Run(":8080")
}

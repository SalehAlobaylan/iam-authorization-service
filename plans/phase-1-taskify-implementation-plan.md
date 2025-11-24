# Phase 1: Taskify - Detailed Implementation Plan

## Project Overview

**Project Name**: iam-authorization-service (Taskify - Phase 1)  
**Purpose**: Task Management API with advanced IAM (RBAC & ABAC) for Railtronics  
**Framework**: Go with Gin  
**Database**: PostgreSQL  
**Duration**: 4 weeks

---

## Project Structure

```
iam-authorization-service/
├── cmd/
│   └── api/
│       └── main.go                    # Application entry point
├── internal/
│   ├── api/                           # API layer (Gin setup)
│   │   ├── router.go                  # Route definitions
│   │   ├── middleware.go              # Middleware setup
│   │   └── server.go                  # Server initialization
│   ├── handlers/                      # HTTP handlers
│   │   ├── auth_handler.go            # Authentication endpoints
│   │   ├── authz_handler.go           # Authorization endpoints
│   │   ├── task_handler.go            # Task CRUD endpoints
│   │   ├── role_handler.go            # Role management
│   │   └── user_handler.go            # User profile endpoints
│   ├── services/                      # Business logic
│   │   ├── auth_service.go            # Authentication logic
│   │   ├── authz_service.go           # Authorization logic (RBAC/ABAC)
│   │   ├── task_service.go            # Task business logic
│   │   └── user_service.go            # User management logic
│   ├── repository/                    # Data access layer
│   │   ├── user_repository.go
│   │   ├── token_repository.go
│   │   ├── role_repository.go
│   │   ├── permission_repository.go
│   │   └── task_repository.go
│   ├── models/                        # Data models
│   │   ├── user.go
│   │   ├── token.go
│   │   ├── role.go
│   │   ├── permission.go
│   │   └── task.go
│   ├── middleware/                    # Custom middleware
│   │   ├── auth.go                    # JWT validation
│   │   ├── authorization.go           # Permission checking
│   │   └── logging.go                 # Request logging
│   ├── database/                      # Database connection
│   │   └── postgres.go                # PostgreSQL setup
│   └── utils/                         # Utilities
│       ├── jwt.go                     # JWT utilities
│       ├── password.go                # Password hashing
│       ├── validator.go               # Input validation
│       └── errors.go                  # Error handling
├── database-migrations/
│   └── migrations/                    # SQL migration files
├── config/
│   ├── config.go                      # Config struct & loading
│   └── config.yaml                    # Config file
├── scripts/
│   ├── seed.sql                       # Initial data
│   └── run-migrations.sh              # Migration script
├── docs/                              # Documentation
├── tests/                             # Tests
│   ├── integration/
│   └── unit/
├── postman/                           # Postman collection
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── Makefile
└── README.md
```

---

## PHASE 1: PROJECT SETUP & CONFIGURATION

### Task 1.1: Initialize Go Module and Dependencies

**File**: `go.mod`

Update module name and add required dependencies (including GORM):

```go
module github.com/yourusername/iam-authorization-service

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    gorm.io/gorm v1.25.5
    gorm.io/driver/postgres v1.5.4
    github.com/golang-jwt/jwt/v5 v5.2.0
    golang.org/x/crypto v0.17.0
    github.com/google/uuid v1.6.0
    gopkg.in/yaml.v3 v3.0.1
    github.com/golang-migrate/migrate/v4 v4.17.0
)
```

**Commands**:
```bash
go mod tidy
```

### Task 1.2: Create Configuration Management

**File**: `config/config.go`

```go
package config

import (
    "fmt"
    "os"
    "gopkg.in/yaml.v3"
)

type Config struct {
    Env      string         `yaml:"env"`
    Server   ServerConfig   `yaml:"server"`
    Database DatabaseConfig `yaml:"database"`
    JWT      JWTConfig      `yaml:"jwt"`
}

type ServerConfig struct {
    Port string `yaml:"port"`
    Host string `yaml:"host"`
}

type DatabaseConfig struct {
    Host     string `yaml:"host"`
    Port     string `yaml:"port"`
    User     string `yaml:"user"`
    Password string `yaml:"password"`
    DBName   string `yaml:"dbname"`
    SSLMode  string `yaml:"sslmode"`
}

type JWTConfig struct {
    Secret          string `yaml:"secret"`
    AccessTokenTTL  int    `yaml:"access_token_ttl"`  // in seconds
    RefreshTokenTTL int    `yaml:"refresh_token_ttl"` // in seconds
}

func Load() (*Config, error) {
    configPath := os.Getenv("CONFIG_PATH")
    if configPath == "" {
        configPath = "config/config.yaml"
    }

    file, err := os.ReadFile(configPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }

    var cfg Config
    if err := yaml.Unmarshal(file, &cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }

    // Override with environment variables
    if port := os.Getenv("PORT"); port != "" {
        cfg.Server.Port = port
    }
    if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
        cfg.Database.Password = dbPass
    }
    if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
        cfg.JWT.Secret = jwtSecret
    }

    return &cfg, nil
}
```

**File**: `config/config.yaml`

```yaml
env: development

server:
  host: localhost
  port: "8080"

database:
  host: localhost
  port: "5432"
  user: taskmanager
  password: password123
  dbname: taskmanager
  sslmode: disable

jwt:
  secret: your-secret-key-change-in-production
  access_token_ttl: 3600    # 1 hour
  refresh_token_ttl: 3600   # 1 hour
```

**File**: `.env.example`

```env
# Server Configuration
PORT=8080

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=taskmanager
DB_PASSWORD=your-secure-password
DB_NAME=taskmanager
DB_SSLMODE=disable

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Environment
ENV=development
```

---

## PHASE 2: DATABASE SETUP & MIGRATIONS

### Task 2.1: Database Connection with GORM

**File**: `internal/database/postgres.go`

```go
package database

import (
    "fmt"
    "log"

    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
    "github.com/yourusername/iam-authorization-service/config"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

func NewPostgres(cfg config.DatabaseConfig) (*gorm.DB, error) {
    dsn := fmt.Sprintf(
        "host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
        cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
    )

    // GORM logger configuration
    gormConfig := &gorm.Config{
        Logger: logger.Default.LogMode(logger.Info),
    }

    db, err := gorm.Open(postgres.Open(dsn), gormConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %w", err)
    }

    // Get underlying SQL database for connection pool settings
    sqlDB, err := db.DB()
    if err != nil {
        return nil, fmt.Errorf("failed to get underlying database: %w", err)
    }

    // Set connection pool settings
    sqlDB.SetMaxOpenConns(25)
    sqlDB.SetMaxIdleConns(5)

    // Test connection
    if err := sqlDB.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    log.Println("Database connected successfully")
    return db, nil
}

// AutoMigrate runs GORM auto-migration (optional, for development)
func AutoMigrate(db *gorm.DB) error {
    return db.AutoMigrate(
        &models.User{},
        &models.Token{},
        &models.Role{},
        &models.Permission{},
        &models.UserRole{},
        &models.RolePermission{},
        &models.Task{},
    )
}
```

**Note**: We'll use golang-migrate for production migrations, but GORM's AutoMigrate can be useful for development.

### Task 2.2: Migration 000001 - Users Table

**File**: `database-migrations/migrations/000001_create_users_table.up.sql`

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
```

**File**: `database-migrations/migrations/000001_create_users_table.down.sql`

```sql
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;
```

### Task 2.3: Migration 000002 - Tokens Table

**File**: `database-migrations/migrations/000002_create_tokens_table.up.sql`

```sql
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked BOOLEAN DEFAULT false
);

CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_refresh_token ON tokens(refresh_token);
```

**File**: `database-migrations/migrations/000002_create_tokens_table.down.sql`

```sql
DROP INDEX IF EXISTS idx_tokens_refresh_token;
DROP INDEX IF EXISTS idx_tokens_user_id;
DROP TABLE IF EXISTS tokens;
```

### Task 2.4: Migration 000003 - Roles Table

**File**: `database-migrations/migrations/000003_create_roles_table.up.sql`

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**File**: `database-migrations/migrations/000003_create_roles_table.down.sql`

```sql
DROP TABLE IF EXISTS roles;
```

### Task 2.5: Migration 000004 - User Roles Table

**File**: `database-migrations/migrations/000004_create_user_roles_table.up.sql`

```sql
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);
```

**File**: `database-migrations/migrations/000004_create_user_roles_table.down.sql`

```sql
DROP TABLE IF EXISTS user_roles;
```

### Task 2.6: Migration 000005 - Permissions Table

**File**: `database-migrations/migrations/000005_create_permissions_table.up.sql`

```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(resource, action)
);
```

**File**: `database-migrations/migrations/000005_create_permissions_table.down.sql`

```sql
DROP TABLE IF EXISTS permissions;
```

### Task 2.7: Migration 000006 - Role Permissions Table

**File**: `database-migrations/migrations/000006_create_role_permissions_table.up.sql`

```sql
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);
```

**File**: `database-migrations/migrations/000006_create_role_permissions_table.down.sql`

```sql
DROP TABLE IF EXISTS role_permissions;
```

### Task 2.8: Migration 000007 - Tasks Table

**File**: `database-migrations/migrations/000007_create_tasks_table.up.sql`

```sql
CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'medium',
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    due_date TIMESTAMP
);

CREATE INDEX idx_tasks_owner ON tasks(owner_id);
CREATE INDEX idx_tasks_status ON tasks(status);
```

**File**: `database-migrations/migrations/000007_create_tasks_table.down.sql`

```sql
DROP INDEX IF EXISTS idx_tasks_status;
DROP INDEX IF EXISTS idx_tasks_owner;
DROP TABLE IF EXISTS tasks;
```

### Task 2.9: Seed Data Script

**File**: `scripts/seed.sql`

```sql
-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('user', 'Regular user with basic permissions'),
    ('admin', 'Administrator with full access');

-- Insert permissions for profile resource
INSERT INTO permissions (resource, action, description) VALUES
    ('profile', 'read', 'View user profile'),
    ('profile', 'write', 'Update user profile');

-- Insert permissions for user resource
INSERT INTO permissions (resource, action, description) VALUES
    ('user', 'read', 'View users'),
    ('user', 'write', 'Update users'),
    ('user', 'delete', 'Delete users');

-- Insert permissions for task resource
INSERT INTO permissions (resource, action, description) VALUES
    ('task', 'read', 'View tasks'),
    ('task', 'write', 'Create/Update tasks'),
    ('task', 'delete', 'Delete tasks');

-- Assign permissions to 'user' role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM roles WHERE name='user'),
    id
FROM permissions
WHERE (resource = 'profile' AND action IN ('read', 'write'))
   OR (resource = 'task' AND action IN ('read', 'write'));

-- Assign all permissions to 'admin' role
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM roles WHERE name='admin'),
    id
FROM permissions;

-- Create default admin user (password: admin123)
INSERT INTO users (email, password_hash, is_active) VALUES
    ('admin@railtronics.com', '$2a$10$YourHashedPasswordHere', true);

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id)
SELECT 
    (SELECT id FROM users WHERE email='admin@railtronics.com'),
    (SELECT id FROM roles WHERE name='admin');
```

---

## PHASE 3: CORE UTILITIES & MODELS

### Task 3.1: Password Utilities

**File**: `internal/utils/password.go`

```go
package utils

import (
    "golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plain text password using bcrypt
func HashPassword(password string) (string, error) {
    hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hashedBytes), nil
}

// ComparePassword compares a hashed password with a plain text password
func ComparePassword(hashedPassword, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
```

### Task 3.2: JWT Utilities

**File**: `internal/utils/jwt.go`

```go
package utils

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type AccessTokenClaims struct {
    UserID      string                   `json:"user_id"`
    Email       string                   `json:"email"`
    Roles       []string                 `json:"roles"`
    IsAdmin     bool                     `json:"is_admin"`
    Permissions []models.PermissionClaim `json:"permissions"`
    jwt.RegisteredClaims
}

// GenerateAccessToken generates a JWT access token with user claims
func GenerateAccessToken(user models.User, roles []string, permissions []models.PermissionClaim, secret string, ttl int) (string, error) {
    isAdmin := false
    for _, role := range roles {
        if role == "admin" {
            isAdmin = true
            break
        }
    }

    claims := AccessTokenClaims{
        UserID:      user.ID,
        Email:       user.Email,
        Roles:       roles,
        IsAdmin:     isAdmin,
        Permissions: permissions,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(ttl) * time.Second)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "task-manager",
            Subject:   user.ID,
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(secret))
}

// GenerateRefreshToken generates a random secure refresh token
func GenerateRefreshToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

// ValidateAccessToken validates and parses a JWT access token
func ValidateAccessToken(tokenString, secret string) (*AccessTokenClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(secret), nil
    })

    if err != nil {
        return nil, err
    }

    if claims, ok := token.Claims.(*AccessTokenClaims); ok && token.Valid {
        return claims, nil
    }

    return nil, fmt.Errorf("invalid token")
}
```

### Task 3.3: Validator Utilities

**File**: `internal/utils/validator.go`

```go
package utils

import (
    "fmt"
    "regexp"

    "github.com/google/uuid"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail validates email format
func ValidateEmail(email string) error {
    if !emailRegex.MatchString(email) {
        return fmt.Errorf("invalid email format")
    }
    return nil
}

// ValidatePassword validates password complexity
func ValidatePassword(password string) error {
    if len(password) < 8 {
        return fmt.Errorf("password must be at least 8 characters long")
    }
    return nil
}

// ValidateUUID validates UUID format
func ValidateUUID(id string) error {
    if _, err := uuid.Parse(id); err != nil {
        return fmt.Errorf("invalid UUID format")
    }
    return nil
}
```

### Task 3.4: Error Utilities

**File**: `internal/utils/errors.go`

```go
package utils

import "fmt"

type APIError struct {
    StatusCode int
    Message    string
}

func (e *APIError) Error() string {
    return e.Message
}

func NewAPIError(statusCode int, message string) *APIError {
    return &APIError{
        StatusCode: statusCode,
        Message:    message,
    }
}

// Common error constructors
func ValidationError(message string) *APIError {
    return NewAPIError(400, message)
}

func UnauthorizedError(message string) *APIError {
    return NewAPIError(401, message)
}

func ForbiddenError(message string) *APIError {
    return NewAPIError(403, message)
}

func NotFoundError(message string) *APIError {
    return NewAPIError(404, message)
}

func InternalServerError(message string) *APIError {
    return NewAPIError(500, message)
}
```

### Task 3.5: Data Models

**File**: `internal/models/user.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type User struct {
    ID           string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Email        string    `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
    PasswordHash string    `gorm:"type:varchar(255);not null" json:"-"` // Never expose in JSON
    IsActive     bool      `gorm:"default:true" json:"is_active"`
    CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`
    
    // Associations
    Tokens []Token `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
    Roles  []Role  `gorm:"many2many:user_roles;" json:"-"`
    Tasks  []Task  `gorm:"foreignKey:OwnerID;constraint:OnDelete:CASCADE" json:"-"`
}

// BeforeCreate GORM hook to generate UUID
func (u *User) BeforeCreate(tx *gorm.DB) error {
    if u.ID == "" {
        u.ID = uuid.New().String()
    }
    return nil
}

// TableName specifies table name
func (User) TableName() string {
    return "users"
}

type RegisterRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}
```

**File**: `internal/models/token.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type Token struct {
    ID           string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    UserID       string    `gorm:"type:uuid;not null;index" json:"user_id"`
    RefreshToken string    `gorm:"type:varchar(500);uniqueIndex;not null" json:"refresh_token"`
    ExpiresAt    time.Time `gorm:"not null" json:"expires_at"`
    CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
    Revoked      bool      `gorm:"default:false" json:"revoked"`
    
    // Association
    User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// BeforeCreate GORM hook
func (t *Token) BeforeCreate(tx *gorm.DB) error {
    if t.ID == "" {
        t.ID = uuid.New().String()
    }
    return nil
}

// TableName specifies table name
func (Token) TableName() string {
    return "tokens"
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}

type RefreshTokenRequest struct {
    RefreshToken string `json:"refresh_token" binding:"required"`
}
```

**File**: `internal/models/role.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type Role struct {
    ID          string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Name        string    `gorm:"type:varchar(50);uniqueIndex;not null" json:"name"`
    Description string    `gorm:"type:text" json:"description"`
    CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
    
    // Associations
    Users       []User       `gorm:"many2many:user_roles;" json:"-"`
    Permissions []Permission `gorm:"many2many:role_permissions;" json:"-"`
}

// BeforeCreate GORM hook
func (r *Role) BeforeCreate(tx *gorm.DB) error {
    if r.ID == "" {
        r.ID = uuid.New().String()
    }
    return nil
}

// TableName specifies table name
func (Role) TableName() string {
    return "roles"
}

// UserRole join table model
type UserRole struct {
    UserID     string    `gorm:"type:uuid;primaryKey" json:"user_id"`
    RoleID     string    `gorm:"type:uuid;primaryKey" json:"role_id"`
    AssignedAt time.Time `gorm:"autoCreateTime" json:"assigned_at"`
}

// TableName specifies table name
func (UserRole) TableName() string {
    return "user_roles"
}
```

**File**: `internal/models/permission.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type Permission struct {
    ID          string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Resource    string    `gorm:"type:varchar(50);not null" json:"resource"`
    Action      string    `gorm:"type:varchar(50);not null" json:"action"`
    Description string    `gorm:"type:text" json:"description"`
    CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
    
    // Associations
    Roles []Role `gorm:"many2many:role_permissions;" json:"-"`
}

// BeforeCreate GORM hook
func (p *Permission) BeforeCreate(tx *gorm.DB) error {
    if p.ID == "" {
        p.ID = uuid.New().String()
    }
    return nil
}

// TableName specifies table name
func (Permission) TableName() string {
    return "permissions"
}

// RolePermission join table model
type RolePermission struct {
    RoleID       string    `gorm:"type:uuid;primaryKey" json:"role_id"`
    PermissionID string    `gorm:"type:uuid;primaryKey" json:"permission_id"`
    AssignedAt   time.Time `gorm:"autoCreateTime" json:"assigned_at"`
}

// TableName specifies table name
func (RolePermission) TableName() string {
    return "role_permissions"
}

type PermissionClaim struct {
    Resource string   `json:"resource"`
    Actions  []string `json:"actions"`
}
```

**File**: `internal/models/task.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type Task struct {
    ID          string     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Title       string     `gorm:"type:varchar(255);not null" json:"title"`
    Description string     `gorm:"type:text" json:"description"`
    Status      string     `gorm:"type:varchar(50);default:'pending'" json:"status"`
    Priority    string     `gorm:"type:varchar(20);default:'medium'" json:"priority"`
    OwnerID     string     `gorm:"type:uuid;not null;index" json:"owner_id"`
    CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt   time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
    DueDate     *time.Time `gorm:"type:timestamp" json:"due_date,omitempty"`
    
    // Association
    Owner User `gorm:"foreignKey:OwnerID;constraint:OnDelete:CASCADE" json:"-"`
}

// BeforeCreate GORM hook
func (t *Task) BeforeCreate(tx *gorm.DB) error {
    if t.ID == "" {
        t.ID = uuid.New().String()
    }
    return nil
}

// TableName specifies table name
func (Task) TableName() string {
    return "tasks"
}

type CreateTaskRequest struct {
    Title       string     `json:"title" binding:"required"`
    Description string     `json:"description"`
    Status      string     `json:"status"`
    Priority    string     `json:"priority"`
    DueDate     *time.Time `json:"due_date,omitempty"`
}

type UpdateTaskRequest struct {
    Title       *string    `json:"title,omitempty"`
    Description *string    `json:"description,omitempty"`
    Status      *string    `json:"status,omitempty"`
    Priority    *string    `json:"priority,omitempty"`
    DueDate     *time.Time `json:"due_date,omitempty"`
}
```

---

## PHASE 4: REPOSITORIES WITH GORM

### Task 4.1: User Repository with GORM

**File**: `internal/repository/user_repository.go`

```go
package repository

import (
    "fmt"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type UserRepository struct {
    db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
    return &UserRepository{db: db}
}

// Create inserts a new user (GORM auto-generates UUID, prevents SQL injection)
func (r *UserRepository) Create(user *models.User) error {
    return r.db.Create(user).Error
}

// GetByEmail retrieves user by email (GORM safe from SQL injection)
func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
    var user models.User
    if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("user not found")
        }
        return nil, err
    }
    return &user, nil
}

// GetByID retrieves user by ID (GORM safe from SQL injection - CRITICAL FOR RUBRIC)
func (r *UserRepository) GetByID(id string) (*models.User, error) {
    var user models.User
    if err := r.db.First(&user, "id = ?", id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("user not found")
        }
        return nil, err
    }
    return &user, nil
}

// Update updates user information (GORM safe from SQL injection)
func (r *UserRepository) Update(user *models.User) error {
    return r.db.Save(user).Error
}

// UpdatePassword updates only password field
func (r *UserRepository) UpdatePassword(userID, passwordHash string) error {
    return r.db.Model(&models.User{}).
        Where("id = ?", userID).
        Update("password_hash", passwordHash).Error
}

// Delete removes a user (GORM safe from SQL injection)
func (r *UserRepository) Delete(id string) error {
    return r.db.Delete(&models.User{}, "id = ?", id).Error
}

// GetAll retrieves all users (admin function)
func (r *UserRepository) GetAll() ([]models.User, error) {
    var users []models.User
    if err := r.db.Find(&users).Error; err != nil {
        return nil, err
    }
    return users, nil
}
```

### Task 4.2: Token Repository with GORM

**File**: `internal/repository/token_repository.go`

```go
package repository

import (
    "fmt"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
    "time"
)

type TokenRepository struct {
    db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) *TokenRepository {
    return &TokenRepository{db: db}
}

// Create inserts a new refresh token
func (r *TokenRepository) Create(token *models.Token) error {
    return r.db.Create(token).Error
}

// GetByRefreshToken retrieves token by refresh token string
func (r *TokenRepository) GetByRefreshToken(refreshToken string) (*models.Token, error) {
    var token models.Token
    if err := r.db.Where("refresh_token = ?", refreshToken).First(&token).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("token not found")
        }
        return nil, err
    }
    return &token, nil
}

// Revoke marks a refresh token as revoked
func (r *TokenRepository) Revoke(refreshToken string) error {
    return r.db.Model(&models.Token{}).
        Where("refresh_token = ?", refreshToken).
        Update("revoked", true).Error
}

// DeleteExpired removes expired tokens
func (r *TokenRepository) DeleteExpired() error {
    return r.db.Where("expires_at < ?", time.Now()).
        Delete(&models.Token{}).Error
}

// RevokeAllUserTokens revokes all tokens for a user
func (r *TokenRepository) RevokeAllUserTokens(userID string) error {
    return r.db.Model(&models.Token{}).
        Where("user_id = ?", userID).
        Update("revoked", true).Error
}
```

### Task 4.3: Role Repository with GORM

**File**: `internal/repository/role_repository.go`

```go
package repository

import (
    "fmt"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type RoleRepository struct {
    db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *RoleRepository {
    return &RoleRepository{db: db}
}

// GetByName retrieves a role by name
func (r *RoleRepository) GetByName(name string) (*models.Role, error) {
    var role models.Role
    if err := r.db.Where("name = ?", name).First(&role).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("role not found")
        }
        return nil, err
    }
    return &role, nil
}

// GetUserRoles retrieves all roles for a user with JOIN
func (r *RoleRepository) GetUserRoles(userID string) ([]models.Role, error) {
    var roles []models.Role
    if err := r.db.Joins("JOIN user_roles ON user_roles.role_id = roles.id").
        Where("user_roles.user_id = ?", userID).
        Find(&roles).Error; err != nil {
        return nil, err
    }
    return roles, nil
}

// AssignRoleToUser assigns a role to a user
func (r *RoleRepository) AssignRoleToUser(userID, roleID string) error {
    userRole := models.UserRole{
        UserID: userID,
        RoleID: roleID,
    }
    // Use FirstOrCreate to avoid duplicate errors
    return r.db.Where(models.UserRole{UserID: userID, RoleID: roleID}).
        FirstOrCreate(&userRole).Error
}

// RemoveRoleFromUser removes a role from a user
func (r *RoleRepository) RemoveRoleFromUser(userID, roleID string) error {
    return r.db.Where("user_id = ? AND role_id = ?", userID, roleID).
        Delete(&models.UserRole{}).Error
}

// GetAll retrieves all roles
func (r *RoleRepository) GetAll() ([]models.Role, error) {
    var roles []models.Role
    if err := r.db.Find(&roles).Error; err != nil {
        return nil, err
    }
    return roles, nil
}

// Create creates a new role
func (r *RoleRepository) Create(role *models.Role) error {
    return r.db.Create(role).Error
}
```

### Task 4.4: Permission Repository with GORM

**File**: `internal/repository/permission_repository.go`

```go
package repository

import (
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type PermissionRepository struct {
    db *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) *PermissionRepository {
    return &PermissionRepository{db: db}
}

// GetRolePermissions retrieves all permissions for a role
func (r *PermissionRepository) GetRolePermissions(roleID string) ([]models.Permission, error) {
    var permissions []models.Permission
    if err := r.db.Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
        Where("role_permissions.role_id = ?", roleID).
        Find(&permissions).Error; err != nil {
        return nil, err
    }
    return permissions, nil
}

// GetUserPermissions retrieves all permissions for a user (through roles)
func (r *PermissionRepository) GetUserPermissions(userID string) ([]models.Permission, error) {
    var permissions []models.Permission
    if err := r.db.
        Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
        Joins("JOIN user_roles ON user_roles.role_id = role_permissions.role_id").
        Where("user_roles.user_id = ?", userID).
        Distinct().
        Find(&permissions).Error; err != nil {
        return nil, err
    }
    return permissions, nil
}

// GetAll retrieves all permissions
func (r *PermissionRepository) GetAll() ([]models.Permission, error) {
    var permissions []models.Permission
    if err := r.db.Find(&permissions).Error; err != nil {
        return nil, err
    }
    return permissions, nil
}

// AssignPermissionToRole assigns a permission to a role
func (r *PermissionRepository) AssignPermissionToRole(roleID, permissionID string) error {
    rolePermission := models.RolePermission{
        RoleID:       roleID,
        PermissionID: permissionID,
    }
    return r.db.Where(models.RolePermission{RoleID: roleID, PermissionID: permissionID}).
        FirstOrCreate(&rolePermission).Error
}

// RemovePermissionFromRole removes a permission from a role
func (r *PermissionRepository) RemovePermissionFromRole(roleID, permissionID string) error {
    return r.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).
        Delete(&models.RolePermission{}).Error
}

// Create creates a new permission
func (r *PermissionRepository) Create(permission *models.Permission) error {
    return r.db.Create(permission).Error
}
```

### Task 4.5: Task Repository with GORM

**File**: `internal/repository/task_repository.go`

```go
package repository

import (
    "fmt"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type TaskRepository struct {
    db *gorm.DB
}

func NewTaskRepository(db *gorm.DB) *TaskRepository {
    return &TaskRepository{db: db}
}

// Create inserts a new task (GORM prevents SQL injection)
func (r *TaskRepository) Create(task *models.Task) error {
    return r.db.Create(task).Error
}

// GetByID retrieves a task by ID
func (r *TaskRepository) GetByID(id string) (*models.Task, error) {
    var task models.Task
    if err := r.db.Preload("Owner").First(&task, "id = ?", id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("task not found")
        }
        return nil, err
    }
    return &task, nil
}

// GetAll retrieves all tasks (optionally filtered by owner)
func (r *TaskRepository) GetAll(ownerID string) ([]models.Task, error) {
    var tasks []models.Task
    query := r.db.Preload("Owner")
    
    if ownerID != "" {
        query = query.Where("owner_id = ?", ownerID)
    }
    
    if err := query.Order("created_at DESC").Find(&tasks).Error; err != nil {
        return nil, err
    }
    return tasks, nil
}

// GetByOwner retrieves all tasks for a specific owner
func (r *TaskRepository) GetByOwner(ownerID string) ([]models.Task, error) {
    var tasks []models.Task
    if err := r.db.Where("owner_id = ?", ownerID).
        Order("created_at DESC").
        Find(&tasks).Error; err != nil {
        return nil, err
    }
    return tasks, nil
}

// Update updates a task (GORM prevents SQL injection)
func (r *TaskRepository) Update(task *models.Task) error {
    return r.db.Save(task).Error
}

// Delete removes a task (GORM prevents SQL injection)
func (r *TaskRepository) Delete(id string) error {
    return r.db.Delete(&models.Task{}, "id = ?", id).Error
}

// GetWithPagination retrieves tasks with pagination (for stand-out feature)
func (r *TaskRepository) GetWithPagination(ownerID string, page, limit int, sortBy, order string) ([]models.Task, int64, error) {
    var tasks []models.Task
    var total int64
    
    query := r.db.Model(&models.Task{})
    if ownerID != "" {
        query = query.Where("owner_id = ?", ownerID)
    }
    
    // Count total
    query.Count(&total)
    
    // Apply pagination and sorting
    offset := (page - 1) * limit
    orderClause := fmt.Sprintf("%s %s", sortBy, order)
    
    if err := query.Order(orderClause).
        Limit(limit).
        Offset(offset).
        Find(&tasks).Error; err != nil {
        return nil, 0, err
    }
    
    return tasks, total, nil
}
```

### Task 4.6: Update Authentication Service for GORM

**File**: `internal/services/auth_service.go`

```go
package services

import (
    "fmt"
    "time"

    "github.com/yourusername/iam-authorization-service/config"
    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/utils"
)

type AuthService struct {
    userRepo  *repository.UserRepository
    tokenRepo *repository.TokenRepository
    roleRepo  *repository.RoleRepository
    permRepo  *repository.PermissionRepository
    config    *config.Config
}

func NewAuthService(
    userRepo *repository.UserRepository,
    tokenRepo *repository.TokenRepository,
    roleRepo *repository.RoleRepository,
    permRepo *repository.PermissionRepository,
    cfg *config.Config,
) *AuthService {
    return &AuthService{
        userRepo:  userRepo,
        tokenRepo: tokenRepo,
        roleRepo:  roleRepo,
        permRepo:  permRepo,
        config:    cfg,
    }
}

// Register creates new user with default 'user' role (RUBRIC REQUIREMENT)
func (s *AuthService) Register(email, password string) (*models.User, error) {
    // Validate input
    if err := utils.ValidateEmail(email); err != nil {
        return nil, utils.ValidationError(err.Error())
    }
    if err := utils.ValidatePassword(password); err != nil {
        return nil, utils.ValidationError(err.Error())
    }

    // Check if user exists
    if _, err := s.userRepo.GetByEmail(email); err == nil {
        return nil, utils.ValidationError("user already exists")
    }

    // Hash password
    hashedPassword, err := utils.HashPassword(password)
    if err != nil {
        return nil, utils.InternalServerError("failed to hash password")
    }

    // Create user
    user := &models.User{
        Email:        email,
        PasswordHash: hashedPassword,
        IsActive:     true,
    }

    if err := s.userRepo.Create(user); err != nil {
        return nil, utils.InternalServerError("failed to create user")
    }

    // Assign default 'user' role (RUBRIC REQUIREMENT)
    defaultRole, err := s.roleRepo.GetByName("user")
    if err != nil {
        return nil, utils.InternalServerError("failed to get default role")
    }

    if err := s.roleRepo.AssignRoleToUser(user.ID, defaultRole.ID); err != nil {
        return nil, utils.InternalServerError("failed to assign role")
    }

    // Clear password hash before returning
    user.PasswordHash = ""
    return user, nil
}

// Login authenticates user and returns JWT tokens with roles/permissions (RUBRIC REQUIREMENT)
func (s *AuthService) Login(email, password string) (*models.TokenPair, error) {
    // Get user by email
    user, err := s.userRepo.GetByEmail(email)
    if err != nil {
        return nil, utils.UnauthorizedError("invalid credentials")
    }

    // Verify password
    if err := utils.ComparePassword(user.PasswordHash, password); err != nil {
        return nil, utils.UnauthorizedError("invalid credentials")
    }

    // Check if user is active
    if !user.IsActive {
        return nil, utils.UnauthorizedError("user account is inactive")
    }

    // Get user roles (RUBRIC REQUIREMENT)
    roles, err := s.roleRepo.GetUserRoles(user.ID)
    if err != nil {
        return nil, utils.InternalServerError("failed to get user roles")
    }

    roleNames := make([]string, len(roles))
    for i, role := range roles {
        roleNames[i] = role.Name
    }

    // Get user permissions grouped by resource (RUBRIC REQUIREMENT)
    allPermissions, err := s.permRepo.GetUserPermissions(user.ID)
    if err != nil {
        return nil, utils.InternalServerError("failed to get user permissions")
    }

    // Group permissions by resource for JWT claims
    permissionMap := make(map[string][]string)
    for _, perm := range allPermissions {
        permissionMap[perm.Resource] = append(permissionMap[perm.Resource], perm.Action)
    }

    permissions := make([]models.PermissionClaim, 0, len(permissionMap))
    for resource, actions := range permissionMap {
        permissions = append(permissions, models.PermissionClaim{
            Resource: resource,
            Actions:  actions,
        })
    }

    // Generate access token (1 hour) with embedded roles and permissions
    accessToken, err := utils.GenerateAccessToken(*user, roleNames, permissions, s.config.JWT.Secret, s.config.JWT.AccessTokenTTL)
    if err != nil {
        return nil, utils.InternalServerError("failed to generate access token")
    }

    // Generate refresh token (1 hour)
    refreshToken, err := utils.GenerateRefreshToken()
    if err != nil {
        return nil, utils.InternalServerError("failed to generate refresh token")
    }

    // Store refresh token in database
    token := &models.Token{
        UserID:       user.ID,
        RefreshToken: refreshToken,
        ExpiresAt:    time.Now().Add(time.Duration(s.config.JWT.RefreshTokenTTL) * time.Second),
        Revoked:      false,
    }

    if err := s.tokenRepo.Create(token); err != nil {
        return nil, utils.InternalServerError("failed to store refresh token")
    }

    return &models.TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    s.config.JWT.AccessTokenTTL,
    }, nil
}

// Refresh generates new tokens from valid refresh token (RUBRIC REQUIREMENT)
func (s *AuthService) Refresh(refreshToken string) (*models.TokenPair, error) {
    // Get token from database
    token, err := s.tokenRepo.GetByRefreshToken(refreshToken)
    if err != nil {
        return nil, utils.UnauthorizedError("invalid refresh token")
    }

    // Check if revoked
    if token.Revoked {
        return nil, utils.UnauthorizedError("refresh token has been revoked")
    }

    // Check if expired
    if time.Now().After(token.ExpiresAt) {
        return nil, utils.UnauthorizedError("refresh token has expired")
    }

    // Get user
    user, err := s.userRepo.GetByID(token.UserID)
    if err != nil {
        return nil, utils.UnauthorizedError("user not found")
    }

    // Get user roles
    roles, err := s.roleRepo.GetUserRoles(user.ID)
    if err != nil {
        return nil, utils.InternalServerError("failed to get user roles")
    }

    roleNames := make([]string, len(roles))
    for i, role := range roles {
        roleNames[i] = role.Name
    }

    // Get user permissions
    allPermissions, err := s.permRepo.GetUserPermissions(user.ID)
    if err != nil {
        return nil, utils.InternalServerError("failed to get user permissions")
    }

    // Group permissions by resource
    permissionMap := make(map[string][]string)
    for _, perm := range allPermissions {
        permissionMap[perm.Resource] = append(permissionMap[perm.Resource], perm.Action)
    }

    permissions := make([]models.PermissionClaim, 0, len(permissionMap))
    for resource, actions := range permissionMap {
        permissions = append(permissions, models.PermissionClaim{
            Resource: resource,
            Actions:  actions,
        })
    }

    // Generate new access token
    newAccessToken, err := utils.GenerateAccessToken(*user, roleNames, permissions, s.config.JWT.Secret, s.config.JWT.AccessTokenTTL)
    if err != nil {
        return nil, utils.InternalServerError("failed to generate access token")
    }

    // Generate new refresh token
    newRefreshToken, err := utils.GenerateRefreshToken()
    if err != nil {
        return nil, utils.InternalServerError("failed to generate refresh token")
    }

    // Revoke old refresh token
    if err := s.tokenRepo.Revoke(refreshToken); err != nil {
        return nil, utils.InternalServerError("failed to revoke old token")
    }

    // Store new refresh token
    newToken := &models.Token{
        UserID:       user.ID,
        RefreshToken: newRefreshToken,
        ExpiresAt:    time.Now().Add(time.Duration(s.config.JWT.RefreshTokenTTL) * time.Second),
        Revoked:      false,
    }

    if err := s.tokenRepo.Create(newToken); err != nil {
        return nil, utils.InternalServerError("failed to store new refresh token")
    }

    return &models.TokenPair{
        AccessToken:  newAccessToken,
        RefreshToken: newRefreshToken,
        ExpiresIn:    s.config.JWT.AccessTokenTTL,
    }, nil
}

// Logout revokes a refresh token
func (s *AuthService) Logout(refreshToken string) error {
    return s.tokenRepo.Revoke(refreshToken)
}
```

### Task 4.7: Update Server Initialization for GORM

**File**: `internal/api/server.go`

```go
package api

import (
    "fmt"
    "log"

    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/config"
    "github.com/yourusername/iam-authorization-service/internal/handlers"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/services"
)

type Server struct {
    config *config.Config
    router *gin.Engine
    db     *gorm.DB
}

func NewServer(cfg *config.Config, db *gorm.DB) *Server {
    // Set Gin mode
    if cfg.Env == "production" {
        gin.SetMode(gin.ReleaseMode)
    }

    server := &Server{
        config: cfg,
        router: gin.Default(),
        db:     db,
    }

    // Initialize repositories
    repos := initRepositories(db)
    
    // Initialize services
    svcs := initServices(repos, cfg)
    
    // Initialize handlers
    handlers := initHandlers(svcs)
    
    // Setup routes
    setupRoutes(server.router, handlers, svcs)
    
    return server
}

func (s *Server) Run() error {
    addr := fmt.Sprintf(":%s", s.config.Server.Port)
    log.Printf("Server starting on %s", addr)
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
    Authz *services.AuthzService
    Task  *services.TaskService
    User  *services.UserService
}

func initServices(repos *Repositories, cfg *config.Config) *Services {
    authzService := services.NewAuthzService(repos.Role, repos.Permission)
    
    return &Services{
        Auth:  services.NewAuthService(repos.User, repos.Token, repos.Role, repos.Permission, cfg),
        Authz: authzService,
        Task:  services.NewTaskService(repos.Task, authzService),
        User:  services.NewUserService(repos.User),
    }
}

type Handlers struct {
    Auth *handlers.AuthHandler
    Task *handlers.TaskHandler
    User *handlers.UserHandler
    Role *handlers.RoleHandler
}

func initHandlers(svcs *Services) *Handlers {
    return &Handlers{
        Auth: handlers.NewAuthHandler(svcs.Auth),
        Task: handlers.NewTaskHandler(svcs.Task),
        User: handlers.NewUserHandler(svcs.User, svcs.Authz),
        Role: handlers.NewRoleHandler(svcs.Authz),
    }
}
```

### Task 4.8: Update Main Entry Point for GORM

**File**: `cmd/api/main.go`

```go
package main

import (
    "log"

    "github.com/yourusername/iam-authorization-service/config"
    "github.com/yourusername/iam-authorization-service/internal/api"
    "github.com/yourusername/iam-authorization-service/internal/database"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // Initialize GORM database connection
    db, err := database.NewPostgres(cfg.Database)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }

    log.Println("Database connection established")

    // Optional: Run auto-migration in development
    // if cfg.Env == "development" {
    //     if err := database.AutoMigrate(db); err != nil {
    //         log.Fatalf("Failed to auto-migrate: %v", err)
    //     }
    // }

    // Initialize and start server
    server := api.NewServer(cfg, db)
    
    log.Printf("Starting Taskify server on port %s", cfg.Server.Port)
    if err := server.Run(); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}
```

---

## DEVELOPMENT TIMELINE (4 WEEKS)

### Week 1: Foundation & Authentication
- [ ] Complete Phase 1: Project Setup & Configuration
- [ ] Complete Phase 2: Database Setup & Migrations (000001-000002)
- [ ] Complete Phase 3: Core Utilities & Models
- [ ] Complete Phase 4: User Registration & Login
- [ ] Test registration and login endpoints manually
- [ ] Verify JWT token generation and validation

### Week 2: Authorization (RBAC & ABAC)
- [ ] Complete Phase 2: Database Migrations (000003-000006 for roles/permissions)
- [ ] Complete Phase 5: Authorization Service & Middleware
- [ ] Update Login service to include roles/permissions in JWT
- [ ] Test permission checking middleware
- [ ] Run seed data to populate roles and permissions

### Week 3: Task Management & User Profile
- [ ] Complete Phase 2: Database Migration (000007 - Tasks table)
- [ ] Complete Phase 6: Task Management CRUD
- [ ] Complete Phase 7: User Profile Endpoint (with SQL injection prevention)
- [ ] Test all task endpoints with different user roles
- [ ] Verify ownership checks and admin overrides

### Week 4: Integration, Testing & Polish
- [ ] Complete Phase 8: API Server & Routing Setup
- [ ] Complete Phase 9: Testing & Deployment
- [ ] Create Postman collection for API testing
- [ ] Write README documentation
- [ ] Set up Docker Compose for deployment
- [ ] Perform end-to-end testing
- [ ] Optional: Add stand-out features (Swagger, unit tests, pagination)

---

## CRITICAL RUBRIC REQUIREMENTS CHECKLIST

### Authentication (Must Have)
- [ ] User registration endpoint stores hashed passwords (bcrypt) in PostgreSQL `users` table
- [ ] User login endpoint returns JWT `access_token` and `refresh_token` (both 1 hour validity)
- [ ] `tokens` table stores `refresh_token` with expiry timestamp
- [ ] Refresh token endpoint validates refresh token and returns new `access_token` and `refresh_token`

### Task Management (Must Have)
- [ ] `tasks` table migration created with ascending numeric prefix (000007_)
- [ ] Task CRUD operations implemented in `handlers/task_handler.go` and `services/task_service.go`
- [ ] All task operations respect user permissions

### Authorization Database Schema (Must Have)
- [ ] `roles` table: id (UUID), name (unique string)
- [ ] `user_roles` table: user_id (UUID FK), role_id (UUID FK)
- [ ] `permissions` table: id (UUID), resource (string), action (string)
- [ ] `role_permissions` table: role_id (UUID FK), permission_id (UUID FK)

### Default Data Population (Must Have)
- [ ] Two roles created: 'user' and 'admin'
- [ ] Admin user account created with 'admin' role assigned
- [ ] Permissions defined for profile, user, and task resources (read, write, delete actions)
- [ ] Role-permission mappings: 'user' role has limited permissions, 'admin' has all

### RBAC & ABAC Implementation (Must Have)
- [ ] Registration automatically assigns default 'user' role to new users
- [ ] Login includes user's role in JWT `access_token` claims
- [ ] Login includes user's permissions in JWT `access_token` claims
- [ ] Authorization middleware verifies `access_token` on protected endpoints
- [ ] Authorization middleware enforces role-based and permission-based access control

### SQL Injection Prevention (Must Have)
- [ ] Get User Profile endpoint uses parameterized queries ($1, $2, etc.)
- [ ] ALL database queries across entire application use parameterized queries
- [ ] NO string concatenation used in any SQL query

### Security Best Practices (Must Have)
- [ ] All passwords hashed with bcrypt before storage
- [ ] JWT tokens properly signed with secret key
- [ ] Authorization checks on all protected endpoints
- [ ] Proper HTTP status codes (200, 201, 400, 401, 403, 404, 500)
- [ ] Input validation on all request handlers
- [ ] Error messages don't expose sensitive information

---

## STAND-OUT FEATURES (OPTIONAL - FOR BONUS POINTS)

### 1. Postman Collection
**File**: `postman/Taskify-API.postman_collection.json`
- Complete API test collection with all endpoints
- Pre-request scripts for automatic token management
- Environment variables for base URL, tokens
- Organized folders: Auth, Tasks, Users, Admin
- Example requests for success and error cases

### 2. Swagger/OpenAPI Documentation
**Tool**: Install `swag` - `go install github.com/swaggo/swag/cmd/swag@latest`
**File**: `docs/swagger.yaml`
- OpenAPI 3.0 specification
- Document all endpoints with request/response schemas
- Security schemes (Bearer JWT)
- Add swagger annotations to handlers
- Generate: `swag init -g cmd/api/main.go`
- Serve at `/swagger/index.html`

### 3. Pagination & Sorting for Tasks API
**Implementation**: Modify `internal/handlers/task_handler.go` List method
- Accept query params: `page`, `limit`, `sort_by`, `order`
- Default: page=1, limit=10, sort_by=created_at, order=desc
- Implement in repository with SQL LIMIT, OFFSET, ORDER BY
- Return metadata: `{ "tasks": [], "page": 1, "limit": 10, "total": 50 }`

### 4. Unit Tests
**Directory**: `tests/unit/`
- Test password hashing/comparison
- Test JWT generation/validation
- Test authorization logic (HasPermission, HasRole)
- Test service layer with mocked repositories
- Use `testify/mock` for mocking
- Run: `make test`

### 5. Integration Tests
**Directory**: `tests/integration/`
- Test complete registration flow
- Test login and token refresh
- Test task CRUD with authorization
- Use test database
- Clean up after each test
- Run: `make test-integration`

### 6. Comprehensive README
**File**: `README.md`
- Project overview and key features
- Technology stack (Go, Gin, PostgreSQL, JWT)
- Architecture diagram
- Setup instructions (prerequisites, environment variables, migrations)
- API endpoints documentation
- Testing instructions
- Deployment guide (Docker)
- Contributing guidelines

### 7. Docker Compose for Easy Deployment
**File**: `docker-compose.yml`
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: taskmanager
      POSTGRES_PASSWORD: password123
      POSTGRES_DB: taskmanager
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  api:
    build: .
    ports:
      - "8080:8080"
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_USER: taskmanager
      DB_PASSWORD: password123
      DB_NAME: taskmanager
      JWT_SECRET: your-secret-key
    depends_on:
      - postgres

volumes:
  postgres_data:
```

---

## QUICK START COMMANDS

```bash
# Install dependencies
go mod download

# Run database migrations
make migrate-up

# Seed initial data (roles, permissions, admin user)
make seed

# Run the application
make run

# Run tests
make test

# Run with Docker
make docker-up

# View logs
make docker-logs

# Stop Docker containers
make docker-down
```

---

## KEY IMPLEMENTATION NOTES

1. **Follow the Development Order**: Complete phases in sequence to avoid dependency issues
2. **Test as You Build**: Test each endpoint immediately after implementation
3. **GORM Usage**: Use GORM methods (Create, Find, Where, etc.) - GORM automatically prevents SQL injection
4. **GORM Tags**: All models must have proper GORM struct tags for column types, indexes, and constraints
5. **JWT Claims**: Embed roles and permissions in access_token for efficient authorization
6. **Ownership Checks**: Regular users can only access their own resources; admins bypass this
7. **Error Handling**: Return appropriate HTTP status codes and clear error messages
8. **Database Migrations**: Use golang-migrate for migrations, but GORM for queries
9. **Seed Data**: Must include default roles, permissions, and admin user
10. **Documentation**: Comment complex logic and maintain clear README
11. **GORM Associations**: Use Preload() to load related data, define associations in models
12. **SQL Injection Prevention**: GORM automatically uses parameterized queries - never use raw SQL strings

---

## COMMON PITFALLS TO AVOID

1. ❌ **SQL Injection**: Never bypass GORM - always use GORM methods (Where, Create, Find, etc.)
2. ❌ **Missing GORM Tags**: All models must have proper gorm struct tags
3. ❌ **Exposing Password Hashes**: Always clear password_hash before returning user objects (use json:"-" tag)
4. ❌ **Missing Authorization**: Every protected endpoint must have middleware
5. ❌ **Weak Passwords**: Enforce minimum 8 characters
6. ❌ **Expired Tokens**: Check token expiry in refresh endpoint
7. ❌ **Missing Default Role**: Registration must assign 'user' role
8. ❌ **Empty JWT Claims**: Login must include roles and permissions in token
9. ❌ **Incorrect Status Codes**: Use 401 for auth issues, 403 for authorization, 404 for not found
10. ❌ **Forgetting Preload**: Use db.Preload() to load associations, or you'll get empty related data

---

## SUCCESS CRITERIA

Your Phase 1 implementation is complete when:

✅ Users can register with email/password  
✅ Users can login and receive JWT tokens  
✅ Refresh token mechanism works correctly  
✅ Default 'user' role is assigned on registration  
✅ JWT tokens contain roles and permissions  
✅ Authorization middleware protects endpoints  
✅ Tasks can be created, read, updated, deleted  
✅ Users can only access their own tasks  
✅ Admins can access all tasks and users  
✅ All SQL queries use parameterized queries  
✅ Database migrations run successfully  
✅ Seed data populates correctly  
✅ All rubric requirements are met  

---

## RESOURCES & REFERENCES

- **Go Documentation**: https://golang.org/doc/
- **Gin Framework**: https://gin-gonic.com/docs/
- **GORM Documentation**: https://gorm.io/docs/
- **GORM PostgreSQL**: https://gorm.io/docs/connecting_to_the_database.html#PostgreSQL
- **PostgreSQL**: https://www.postgresql.org/docs/
- **JWT**: https://jwt.io/
- **golang-migrate**: https://github.com/golang-migrate/migrate
- **bcrypt**: https://pkg.go.dev/golang.org/x/crypto/bcrypt
- **GORM Associations**: https://gorm.io/docs/associations.html

---

*End of Phase 1 Implementation Plan*

**Note**: For complete code implementations of Phases 4-9, refer to the conversation history or request detailed code for specific components.



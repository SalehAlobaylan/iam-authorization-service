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

Update module name and add required dependencies:

```go
module github.com/yourusername/iam-authorization-service

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
    github.com/golang-jwt/jwt/v5 v5.2.0
    golang.org/x/crypto v0.17.0
    github.com/google/uuid v1.5.0
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

### Task 2.1: Database Connection

**File**: `internal/database/postgres.go`

```go
package database

import (
    "database/sql"
    "fmt"
    _ "github.com/lib/pq"
    "github.com/yourusername/iam-authorization-service/config"
)

func NewPostgres(cfg config.DatabaseConfig) (*sql.DB, error) {
    connStr := fmt.Sprintf(
        "host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
        cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
    )

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }

    // Test connection
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    // Set connection pool settings
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)

    return db, nil
}
```

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

import "time"

type User struct {
    ID           string    `json:"id"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"` // Never expose in JSON
    IsActive     bool      `json:"is_active"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

type RegisterRequest struct {
    Email    string `json:"email" binding:"required"`
    Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
    Email    string `json:"email" binding:"required"`
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

import "time"

type Token struct {
    ID           string    `json:"id"`
    UserID       string    `json:"user_id"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresAt    time.Time `json:"expires_at"`
    CreatedAt    time.Time `json:"created_at"`
    Revoked      bool      `json:"revoked"`
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

import "time"

type Role struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
}
```

**File**: `internal/models/permission.go`

```go
package models

import "time"

type Permission struct {
    ID          string    `json:"id"`
    Resource    string    `json:"resource"`
    Action      string    `json:"action"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
}

type PermissionClaim struct {
    Resource string   `json:"resource"`
    Actions  []string `json:"actions"`
}
```

**File**: `internal/models/task.go`

```go
package models

import "time"

type Task struct {
    ID          string     `json:"id"`
    Title       string     `json:"title"`
    Description string     `json:"description"`
    Status      string     `json:"status"`
    Priority    string     `json:"priority"`
    OwnerID     string     `json:"owner_id"`
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
    DueDate     *time.Time `json:"due_date,omitempty"`
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

## PHASE 4: USER REGISTRATION & LOGIN (RUBRIC REQUIREMENT 1)

*Due to message length limitations, the remaining phases (4-9) including:*
- **Phase 4**: Repositories & Authentication Service Implementation
- **Phase 5**: Authorization (RBAC & ABAC) with Middleware
- **Phase 6**: Task Management CRUD APIs
- **Phase 7**: User Profile Endpoint (SQL Injection Fix)
- **Phase 8**: API Server Setup & Routing
- **Phase 9**: Testing, Deployment & Stand-Out Features

*Will be provided in a separate detailed implementation document. Each phase includes:*
- Complete code for all repositories (user, token, role, permission, task)
- Service layer implementations
- Handler implementations
- Middleware (auth, authorization, logging)
- Router setup with proper permission checks
- Docker configuration
- Makefile for development
- Optional: Postman collection, Swagger docs, unit tests, integration tests

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
3. **Parameterized Queries**: ALWAYS use $1, $2, etc. - Never concatenate strings in SQL
4. **JWT Claims**: Embed roles and permissions in access_token for efficient authorization
5. **Ownership Checks**: Regular users can only access their own resources; admins bypass this
6. **Error Handling**: Return appropriate HTTP status codes and clear error messages
7. **Database Migrations**: Use ascending numeric prefixes (000001, 000002, etc.)
8. **Seed Data**: Must include default roles, permissions, and admin user
9. **Documentation**: Comment complex logic and maintain clear README

---

## COMMON PITFALLS TO AVOID

1. ❌ **SQL Injection**: Never use string concatenation - always use parameterized queries
2. ❌ **Exposing Password Hashes**: Always clear password_hash before returning user objects
3. ❌ **Missing Authorization**: Every protected endpoint must have middleware
4. ❌ **Weak Passwords**: Enforce minimum 8 characters
5. ❌ **Expired Tokens**: Check token expiry in refresh endpoint
6. ❌ **Missing Default Role**: Registration must assign 'user' role
7. ❌ **Empty JWT Claims**: Login must include roles and permissions in token
8. ❌ **Incorrect Status Codes**: Use 401 for auth issues, 403 for authorization, 404 for not found

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
- **PostgreSQL**: https://www.postgresql.org/docs/
- **JWT**: https://jwt.io/
- **golang-migrate**: https://github.com/golang-migrate/migrate
- **bcrypt**: https://pkg.go.dev/golang.org/x/crypto/bcrypt
- **SQL Injection Prevention**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

---

*End of Phase 1 Implementation Plan*

**Note**: For complete code implementations of Phases 4-9, refer to the conversation history or request detailed code for specific components.



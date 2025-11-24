# Phase 2: Generalization - IAM Authorization Service (with GORM)

## Project Overview

**Project Name**: iam-authorization-service (Phase 2 - Full IAM Platform)  
**Purpose**: Transform Taskify into a complete, self-hosted IAM platform with advanced authentication and multi-tenant authorization  
**Key Difference**: Build authentication IN-HOUSE (no Firebase/Auth0) + Multi-tenant + **GORM ORM**  
**Duration**: 6-8 weeks

---

## Vision: From Taskify to IAM Platform

### What Changes in Phase 2

```
┌─────────────────────────────────────────────────────────────────┐
│ FROM: Taskify (Single-tenant task management)                  │
│ TO: IAM Platform (Multi-tenant auth service for any app)       │
└─────────────────────────────────────────────────────────────────┘

AUTHENTICATION:
  Before: Basic (email/password + JWT)
  After:  Complete (OAuth, MFA, email verification, password reset,
          magic links, account lockout, session management)

AUTHORIZATION:
  Before: RBAC/ABAC for tasks only
  After:  RBAC/ABAC for any resource type + multi-tenant

ARCHITECTURE:
  Before: Monolithic app for tasks
  After:  Platform-as-a-Service for external applications

DATABASE:
  Before: GORM with single-tenant models
  After:  GORM with multi-tenant models + associations

USE CASE:
  Before: Task management only
  After:  Any application can use for IAM needs
```

---

## Core Principles

### 1. Self-Hosted Authentication (No External Providers)

**Key Decision**: Build ALL authentication features in-house.

**Why?**

- Full control over authentication flow
- No vendor lock-in (no Firebase/Auth0 dependency)
- Custom security policies
- Cost-effective at scale
- Learning opportunity for enterprise IAM
- Data sovereignty

**What This Means**:

- Implement OAuth 2.0 server ourselves
- Handle social login integration directly (Google/GitHub APIs)
- Build email service integration (SendGrid/SES as delivery only)
- Implement MFA/2FA from scratch
- Create password reset and email verification flows
- Manage complete session lifecycle

### 2. GORM ORM for All Database Operations

**Why GORM?**

- Automatic SQL injection prevention
- Type-safe database operations
- Built-in associations (many-to-many, foreign keys)
- Clean, readable code
- Automatic migration capabilities
- Transaction support
- Scopes for reusable query logic (tenant isolation)

### 3. Multi-Tenant Architecture

Every resource becomes tenant-scoped using GORM:

- Multiple organizations (tenants) use same IAM service
- Complete data isolation via tenant_id filtering
- Each tenant has own users, roles, permissions, policies
- Tenant admins manage own IAM configuration
- GORM scopes for automatic tenant filtering

### 4. Dynamic Resource Registration

External applications register resources via API:

- Apps define resource types (orders, invoices, documents)
- Apps define actions for each resource type
- IAM service manages permissions using GORM models
- Flexible and extensible

---

## Updated Project Structure

```
iam-authorization-service/
├── cmd/
│   ├── api/
│   │   └── main.go                        # Main API server (GORM init)
│   └── worker/
│       └── main.go                         # Background jobs
│
├── internal/
│   ├── api/
│   │   ├── router.go                       # Enhanced routing
│   │   ├── middleware.go                   # GORM-aware middleware
│   │   └── server.go                       # Server with GORM
│   │
│   ├── handlers/                           # HTTP handlers
│   │   ├── auth_handler.go                 # Enhanced authentication
│   │   ├── oauth_handler.go                # OAuth 2.0 endpoints (NEW)
│   │   ├── mfa_handler.go                  # MFA management (NEW)
│   │   ├── email_verification_handler.go   # Email verification (NEW)
│   │   ├── password_reset_handler.go       # Password reset (NEW)
│   │   ├── authz_handler.go                # Authorization
│   │   ├── tenant_handler.go               # Tenant management (NEW)
│   │   ├── resource_handler.go             # Resource registration (NEW)
│   │   ├── user_handler.go                 # User management
│   │   ├── task_handler.go                 # Demo app (optional)
│   │   └── webhook_handler.go              # Webhooks (NEW)
│   │
│   ├── services/                           # Business logic
│   │   ├── auth_service.go                 # Enhanced auth
│   │   ├── oauth_service.go                # OAuth 2.0 logic (NEW)
│   │   ├── social_login_service.go         # Google/GitHub (NEW)
│   │   ├── mfa_service.go                  # TOTP/SMS (NEW)
│   │   ├── email_service.go                # Email delivery (NEW)
│   │   ├── verification_service.go         # Email verify (NEW)
│   │   ├── password_service.go             # Reset flows (NEW)
│   │   ├── authz_service.go                # Multi-tenant authz
│   │   ├── tenant_service.go               # Tenant logic (NEW)
│   │   ├── resource_service.go             # Dynamic resources (NEW)
│   │   ├── session_service.go              # Sessions (NEW)
│   │   └── audit_service.go                # Audit logging (NEW)
│   │
│   ├── repository/                         # GORM repositories
│   │   ├── user_repository.go              # Multi-tenant GORM
│   │   ├── token_repository.go             # GORM
│   │   ├── tenant_repository.go            # (NEW) GORM
│   │   ├── oauth_client_repository.go      # (NEW) GORM
│   │   ├── mfa_repository.go               # (NEW) GORM
│   │   ├── verification_repository.go      # (NEW) GORM
│   │   ├── password_reset_repository.go    # (NEW) GORM
│   │   ├── resource_type_repository.go     # Enhanced GORM
│   │   ├── role_repository.go              # Multi-tenant GORM
│   │   ├── permission_repository.go        # Multi-tenant GORM
│   │   ├── session_repository.go           # (NEW) GORM
│   │   └── audit_repository.go             # (NEW) GORM
│   │
│   ├── models/                             # GORM models
│   │   ├── user.go                         # Enhanced with GORM tags
│   │   ├── tenant.go                       # (NEW) GORM model
│   │   ├── oauth.go                        # (NEW) GORM model
│   │   ├── mfa.go                          # (NEW) GORM model
│   │   ├── verification.go                 # (NEW) GORM model
│   │   ├── password_reset.go               # (NEW) GORM model
│   │   ├── session.go                      # (NEW) GORM model
│   │   ├── resource_type.go                # Enhanced GORM
│   │   ├── role.go                         # Multi-tenant GORM
│   │   ├── permission.go                   # Multi-tenant GORM
│   │   └── audit.go                        # (NEW) GORM model
│   │
│   ├── middleware/
│   │   ├── auth.go                         # JWT validation
│   │   ├── tenant.go                       # Tenant isolation (NEW)
│   │   ├── authorization.go                # Permission checking
│   │   └── rate_limit.go                   # (NEW)
│   │
│   ├── oauth/                              # OAuth 2.0 (NEW)
│   │   ├── server.go
│   │   ├── authorization.go
│   │   └── token.go
│   │
│   ├── providers/                          # Social login (NEW)
│   │   ├── google.go
│   │   ├── github.go
│   │   └── provider.go
│   │
│   ├── email/                              # Email service (NEW)
│   │   ├── client.go
│   │   ├── sendgrid.go
│   │   └── templates.go
│   │
│   ├── database/
│   │   └── postgres.go                     # GORM connection
│   │
│   └── utils/
│       ├── jwt.go
│       ├── password.go
│       ├── totp.go                         # (NEW)
│       └── validator.go
│
├── pkg/                                    # Public SDK
│   └── iamsdk/
│       ├── client.go
│       ├── auth.go
│       └── authz.go
│
├── database-migrations/
│   └── migrations/                         # golang-migrate files
│
├── examples/                               # Example apps
│   ├── ecommerce-app/
│   └── taskify-client/
│
├── config/
│   ├── config.go
│   └── config.yaml
│
├── docker-compose.yml
├── Dockerfile
├── Makefile
└── README.md
```

---

## PHASE 1: MULTI-TENANT FOUNDATION

### Task 1.1: Multi-Tenant Database Migrations

**Migration 000008**: `create_tenants_table.up.sql`

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(100) UNIQUE,
    status VARCHAR(50) DEFAULT 'active',
    plan VARCHAR(50) DEFAULT 'free',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX idx_tenants_status ON tenants(status);
```

**Migration 000009**: `add_tenant_id_to_existing_tables.up.sql`

```sql
-- Add tenant_id to all existing tables
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP;
CREATE INDEX idx_users_tenant ON users(tenant_id);

ALTER TABLE roles ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_roles_tenant ON roles(tenant_id);

ALTER TABLE permissions ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE permissions ADD COLUMN is_global BOOLEAN DEFAULT false;
CREATE INDEX idx_permissions_tenant ON permissions(tenant_id);

ALTER TABLE tasks ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_tasks_tenant ON tasks(tenant_id);

-- Create default tenant for existing data
INSERT INTO tenants (name, subdomain, status) VALUES ('Default', 'default', 'active');
UPDATE users SET tenant_id = (SELECT id FROM tenants WHERE subdomain = 'default');
UPDATE roles SET tenant_id = (SELECT id FROM tenants WHERE subdomain = 'default');
UPDATE tasks SET tenant_id = (SELECT id FROM tenants WHERE subdomain = 'default');
```

### Task 1.2: Tenant GORM Model

**File**: `internal/models/tenant.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "gorm.io/datatypes"
)

type Tenant struct {
    ID        string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Name      string         `gorm:"type:varchar(255);not null" json:"name"`
    Subdomain string         `gorm:"type:varchar(100);uniqueIndex" json:"subdomain"`
    Status    string         `gorm:"type:varchar(50);default:'active';index" json:"status"`
    Plan      string         `gorm:"type:varchar(50);default:'free'" json:"plan"`
    Settings  datatypes.JSON `gorm:"type:jsonb;default:'{}'" json:"settings"`
    CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`

    // Associations (all tenant-scoped data)
    Users       []User       `gorm:"foreignKey:TenantID;constraint:OnDelete:CASCADE" json:"-"`
    Roles       []Role       `gorm:"foreignKey:TenantID;constraint:OnDelete:CASCADE" json:"-"`
    Permissions []Permission `gorm:"foreignKey:TenantID;constraint:OnDelete:CASCADE" json:"-"`
    Tasks       []Task       `gorm:"foreignKey:TenantID;constraint:OnDelete:CASCADE" json:"-"`
}

func (t *Tenant) BeforeCreate(tx *gorm.DB) error {
    if t.ID == "" {
        t.ID = uuid.New().String()
    }
    return nil
}

func (Tenant) TableName() string {
    return "tenants"
}

type CreateTenantRequest struct {
    Name       string                 `json:"name" binding:"required"`
    Subdomain  string                 `json:"subdomain" binding:"required"`
    AdminEmail string                 `json:"admin_email" binding:"required,email"`
    AdminPassword string              `json:"admin_password" binding:"required,min=8"`
    Plan       string                 `json:"plan"`
    Settings   map[string]interface{} `json:"settings"`
}
```

### Task 1.3: Update Phase 1 Models for Multi-Tenancy

**File**: `internal/models/user.go` (Phase 2 enhancement)

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type User struct {
    ID              string     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Email           string     `gorm:"type:varchar(255);not null" json:"email"`
    PasswordHash    string     `gorm:"type:varchar(255);not null" json:"-"`
    IsActive        bool       `gorm:"default:true" json:"is_active"`
    EmailVerified   bool       `gorm:"default:false" json:"email_verified"` // NEW
    EmailVerifiedAt *time.Time `gorm:"type:timestamp" json:"email_verified_at,omitempty"` // NEW
    TenantID        string     `gorm:"type:uuid;index;not null" json:"tenant_id"` // NEW
    CreatedAt       time.Time  `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt       time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

    // Associations
    Tenant             Tenant              `gorm:"foreignKey:TenantID" json:"-"` // NEW
    Tokens             []Token             `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
    Roles              []Role              `gorm:"many2many:user_roles;" json:"-"`
    Tasks              []Task              `gorm:"foreignKey:OwnerID;constraint:OnDelete:CASCADE" json:"-"`
    MFASettings        *MFASettings        `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"` // NEW
    EmailVerifications []EmailVerification `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"` // NEW
    PasswordResets     []PasswordReset     `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"` // NEW
}

// Composite unique index: email + tenant_id (same email different tenants)
func (User) GormIndexes() []string {
    return []string{"idx_users_email_tenant:email,tenant_id,unique"}
}
```

**File**: `internal/models/role.go` (Phase 2 enhancement)

```go
// Add tenant_id to Role model:
type Role struct {
    ID          string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Name        string    `gorm:"type:varchar(50);not null" json:"name"`
    Description string    `gorm:"type:text" json:"description"`
    TenantID    string    `gorm:"type:uuid;index;not null" json:"tenant_id"` // NEW
    CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`

    // Associations
    Tenant      Tenant       `gorm:"foreignKey:TenantID" json:"-"` // NEW
    Users       []User       `gorm:"many2many:user_roles;" json:"-"`
    Permissions []Permission `gorm:"many2many:role_permissions;" json:"-"`
}

// Composite unique index: name + tenant_id
func (Role) GormIndexes() []string {
    return []string{"idx_roles_name_tenant:name,tenant_id,unique"}
}
```

### Task 1.4: Tenant Repository with GORM

**File**: `internal/repository/tenant_repository.go`

```go
package repository

import (
    "fmt"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type TenantRepository struct {
    db *gorm.DB
}

func NewTenantRepository(db *gorm.DB) *TenantRepository {
    return &TenantRepository{db: db}
}

// Create inserts a new tenant (GORM prevents SQL injection)
func (r *TenantRepository) Create(tenant *models.Tenant) error {
    return r.db.Create(tenant).Error
}

// GetByID retrieves tenant by ID with associations
func (r *TenantRepository) GetByID(id string) (*models.Tenant, error) {
    var tenant models.Tenant
    if err := r.db.Preload("Users").Preload("Roles").
        First(&tenant, "id = ?", id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("tenant not found")
        }
        return nil, err
    }
    return &tenant, nil
}

// GetBySubdomain retrieves tenant by subdomain
func (r *TenantRepository) GetBySubdomain(subdomain string) (*models.Tenant, error) {
    var tenant models.Tenant
    if err := r.db.Where("subdomain = ? AND status = ?", subdomain, "active").
        First(&tenant).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("tenant not found")
        }
        return nil, err
    }
    return &tenant, nil
}

// Update updates tenant information
func (r *TenantRepository) Update(tenant *models.Tenant) error {
    return r.db.Save(tenant).Error
}

// SoftDelete marks tenant as deleted
func (r *TenantRepository) SoftDelete(id string) error {
    return r.db.Model(&models.Tenant{}).
        Where("id = ?", id).
        Update("status", "deleted").Error
}

// GetAll retrieves all active tenants
func (r *TenantRepository) GetAll() ([]models.Tenant, error) {
    var tenants []models.Tenant
    if err := r.db.Where("status = ?", "active").
        Order("created_at DESC").
        Find(&tenants).Error; err != nil {
        return nil, err
    }
    return tenants, nil
}
```

### Task 1.5: Tenant Service

**File**: `internal/services/tenant_service.go`

```go
package services

import (
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/utils"
)

type TenantService struct {
    tenantRepo *repository.TenantRepository
    userRepo   *repository.UserRepository
    roleRepo   *repository.RoleRepository
    permRepo   *repository.PermissionRepository
    db         *gorm.DB
}

func NewTenantService(
    tenantRepo *repository.TenantRepository,
    userRepo *repository.UserRepository,
    roleRepo *repository.RoleRepository,
    permRepo *repository.PermissionRepository,
    db *gorm.DB,
) *TenantService {
    return &TenantService{
        tenantRepo: tenantRepo,
        userRepo:   userRepo,
        roleRepo:   roleRepo,
        permRepo:   permRepo,
        db:         db,
    }
}

// CreateTenant creates new tenant with admin user and default roles (GORM transaction)
func (s *TenantService) CreateTenant(req models.CreateTenantRequest) (*models.Tenant, error) {
    var tenant *models.Tenant

    // Use GORM transaction to ensure atomicity
    err := s.db.Transaction(func(tx *gorm.DB) error {
        // 1. Validate subdomain uniqueness
        if _, err := s.tenantRepo.GetBySubdomain(req.Subdomain); err == nil {
            return utils.ValidationError("subdomain already exists")
        }

        // 2. Create tenant
        tenant = &models.Tenant{
            Name:      req.Name,
            Subdomain: req.Subdomain,
            Status:    "active",
            Plan:      req.Plan,
        }
        if err := tx.Create(tenant).Error; err != nil {
            return utils.InternalServerError("failed to create tenant")
        }

        // 3. Create admin user for tenant
        hashedPassword, _ := utils.HashPassword(req.AdminPassword)
        adminUser := &models.User{
            Email:        req.AdminEmail,
            PasswordHash: hashedPassword,
            TenantID:     tenant.ID,
            IsActive:     true,
            EmailVerified: true, // Admin is pre-verified
        }
        if err := tx.Create(adminUser).Error; err != nil {
            return utils.InternalServerError("failed to create admin user")
        }

        // 4. Create default roles for tenant
        userRole := &models.Role{
            Name:        "user",
            Description: "Regular user",
            TenantID:    tenant.ID,
        }
        adminRole := &models.Role{
            Name:        "admin",
            Description: "Administrator",
            TenantID:    tenant.ID,
        }
        if err := tx.Create(&userRole).Error; err != nil {
            return err
        }
        if err := tx.Create(&adminRole).Error; err != nil {
            return err
        }

        // 5. Assign admin role to admin user
        userRoleAssignment := models.UserRole{
            UserID: adminUser.ID,
            RoleID: adminRole.ID,
        }
        if err := tx.Create(&userRoleAssignment).Error; err != nil {
            return err
        }

        return nil
    })

    return tenant, err
}

// GetTenant retrieves tenant by ID
func (s *TenantService) GetTenant(tenantID string) (*models.Tenant, error) {
    return s.tenantRepo.GetByID(tenantID)
}

// UpdateTenant updates tenant settings
func (s *TenantService) UpdateTenant(tenantID string, req models.UpdateTenantRequest) (*models.Tenant, error) {
    tenant, err := s.tenantRepo.GetByID(tenantID)
    if err != nil {
        return nil, err
    }

    if req.Name != nil {
        tenant.Name = *req.Name
    }
    if req.Status != nil {
        tenant.Status = *req.Status
    }
    if req.Plan != nil {
        tenant.Plan = *req.Plan
    }

    if err := s.tenantRepo.Update(tenant); err != nil {
        return nil, err
    }

    return tenant, nil
}

// DeleteTenant soft deletes a tenant
func (s *TenantService) DeleteTenant(tenantID string) error {
    return s.tenantRepo.SoftDelete(tenantID)
}
```

### Task 1.6: Tenant Isolation Middleware

**File**: `internal/middleware/tenant.go`

```go
package middleware

import (
    "strings"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/yourusername/iam-authorization-service/internal/repository"
)

type TenantMiddleware struct {
    tenantRepo *repository.TenantRepository
}

func NewTenantMiddleware(tenantRepo *repository.TenantRepository) *TenantMiddleware {
    return &TenantMiddleware{tenantRepo: tenantRepo}
}

// ResolveTenant extracts tenant from subdomain, header, or JWT
func (m *TenantMiddleware) ResolveTenant() gin.HandlerFunc {
    return func(c *gin.Context) {
        var tenantID string

        // Option 1: Extract from subdomain (tenant.yourapi.com)
        host := c.Request.Host
        parts := strings.Split(host, ".")
        if len(parts) >= 3 {
            subdomain := parts[0]
            if tenant, err := m.tenantRepo.GetBySubdomain(subdomain); err == nil {
                tenantID = tenant.ID
            }
        }

        // Option 2: Extract from X-Tenant-ID header
        if tenantID == "" {
            tenantID = c.GetHeader("X-Tenant-ID")
        }

        // Option 3: Extract from JWT claims (set during authentication)
        if tenantID == "" {
            tenantID = c.GetString("tenant_id")
        }

        if tenantID == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "tenant not specified"})
            c.Abort()
            return
        }

        // Set tenant_id in context for all downstream handlers/repositories
        c.Set("tenant_id", tenantID)
        c.Next()
    }
}

// RequireTenant ensures tenant is set
func RequireTenant() gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := c.GetString("tenant_id")
        if tenantID == "" {
            c.JSON(http.StatusForbidden, gin.H{"error": "tenant access required"})
            c.Abort()
            return
        }
        c.Next()
    }
}
```

### Task 1.7: GORM Scope for Tenant Isolation

**File**: `internal/repository/scopes.go` (NEW)

```go
package repository

import "gorm.io/gorm"

// TenantScope applies tenant filtering to GORM queries
func TenantScope(tenantID string) func(db *gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        if tenantID != "" {
            return db.Where("tenant_id = ?", tenantID)
        }
        return db
    }
}

// ActiveScope filters for active records
func ActiveScope(db *gorm.DB) *gorm.DB {
    return db.Where("is_active = ?", true)
}

// Example usage in repository:
// func (r *UserRepository) GetAllByTenant(tenantID string) ([]models.User, error) {
//     var users []models.User
//     err := r.db.Scopes(TenantScope(tenantID), ActiveScope).Find(&users).Error
//     return users, err
// }
```

---

## PHASE 2: ENHANCED AUTHENTICATION - EMAIL VERIFICATION

### Task 2.1: Email Verification Database

**Migration 000010**: `create_email_verifications_table.up.sql`

```sql
CREATE TABLE email_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_email_verifications_token ON email_verifications(token);
CREATE INDEX idx_email_verifications_user ON email_verifications(user_id);
```

### Task 2.2: Email Verification GORM Model

**File**: `internal/models/verification.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type EmailVerification struct {
    ID         string     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    UserID     string     `gorm:"type:uuid;not null;index" json:"user_id"`
    Email      string     `gorm:"type:varchar(255);not null" json:"email"`
    Token      string     `gorm:"type:varchar(255);uniqueIndex;not null" json:"token"`
    ExpiresAt  time.Time  `gorm:"not null" json:"expires_at"`
    VerifiedAt *time.Time `gorm:"type:timestamp" json:"verified_at,omitempty"`
    CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`

    // Association
    User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (e *EmailVerification) BeforeCreate(tx *gorm.DB) error {
    if e.ID == "" {
        e.ID = uuid.New().String()
    }
    return nil
}

func (EmailVerification) TableName() string {
    return "email_verifications"
}
```

### Task 2.3: Email Verification Repository (GORM)

**File**: `internal/repository/verification_repository.go`

```go
package repository

import (
    "fmt"
    "time"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type VerificationRepository struct {
    db *gorm.DB
}

func NewVerificationRepository(db *gorm.DB) *VerificationRepository {
    return &VerificationRepository{db: db}
}

// Create inserts verification record
func (r *VerificationRepository) Create(verification *models.EmailVerification) error {
    return r.db.Create(verification).Error
}

// GetByToken retrieves verification by token
func (r *VerificationRepository) GetByToken(token string) (*models.EmailVerification, error) {
    var verification models.EmailVerification
    if err := r.db.Where("token = ?", token).First(&verification).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("verification not found")
        }
        return nil, err
    }
    return &verification, nil
}

// Update updates verification record
func (r *VerificationRepository) Update(verification *models.EmailVerification) error {
    return r.db.Save(verification).Error
}

// DeleteExpired removes expired unverified tokens
func (r *VerificationRepository) DeleteExpired() error {
    return r.db.Where("expires_at < ? AND verified_at IS NULL", time.Now()).
        Delete(&models.EmailVerification{}).Error
}
```

---

## PHASE 3: PASSWORD RESET SYSTEM

### Task 3.1: Password Reset Database

**Migration 000011**: `create_password_resets_table.up.sql`

```sql
CREATE TABLE password_resets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_password_resets_token ON password_resets(token);
CREATE INDEX idx_password_resets_user ON password_resets(user_id);
```

### Task 3.2: Password Reset GORM Model

**File**: `internal/models/password_reset.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type PasswordReset struct {
    ID        string     `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    UserID    string     `gorm:"type:uuid;not null;index" json:"user_id"`
    Token     string     `gorm:"type:varchar(255);uniqueIndex;not null" json:"token"`
    ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
    UsedAt    *time.Time `gorm:"type:timestamp" json:"used_at,omitempty"`
    CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`

    // Association
    User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (p *PasswordReset) BeforeCreate(tx *gorm.DB) error {
    if p.ID == "" {
        p.ID = uuid.New().String()
    }
    return nil
}

func (PasswordReset) TableName() string {
    return "password_resets"
}
```

### Task 3.3: Password Reset Repository (GORM)

**File**: `internal/repository/password_reset_repository.go`

```go
package repository

import (
    "fmt"
    "time"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type PasswordResetRepository struct {
    db *gorm.DB
}

func NewPasswordResetRepository(db *gorm.DB) *PasswordResetRepository {
    return &PasswordResetRepository{db: db}
}

// Create inserts password reset record
func (r *PasswordResetRepository) Create(reset *models.PasswordReset) error {
    return r.db.Create(reset).Error
}

// GetByToken retrieves reset record by token
func (r *PasswordResetRepository) GetByToken(token string) (*models.PasswordReset, error) {
    var reset models.PasswordReset
    if err := r.db.Where("token = ?", token).First(&reset).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("reset token not found")
        }
        return nil, err
    }
    return &reset, nil
}

// Update updates reset record
func (r *PasswordResetRepository) Update(reset *models.PasswordReset) error {
    return r.db.Save(reset).Error
}

// DeleteExpired removes expired unused tokens
func (r *PasswordResetRepository) DeleteExpired() error {
    return r.db.Where("expires_at < ? AND used_at IS NULL", time.Now()).
        Delete(&models.PasswordReset{}).Error
}
```

---

## PHASE 4: MULTI-FACTOR AUTHENTICATION (MFA)

### Task 4.1: MFA Database

**Migration 000012**: `create_mfa_settings_table.up.sql`

```sql
CREATE TABLE mfa_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_method VARCHAR(50),
    totp_secret VARCHAR(255),
    phone_number VARCHAR(20),
    backup_codes JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_mfa_settings_user ON mfa_settings(user_id);
```

### Task 4.2: MFA GORM Model

**File**: `internal/models/mfa.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "gorm.io/datatypes"
)

type MFASettings struct {
    ID          string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    UserID      string         `gorm:"type:uuid;uniqueIndex;not null" json:"user_id"`
    MFAEnabled  bool           `gorm:"default:false" json:"mfa_enabled"`
    MFAMethod   string         `gorm:"type:varchar(50)" json:"mfa_method"` // 'totp'
    TOTPSecret  string         `gorm:"type:varchar(255)" json:"-"` // Never expose
    PhoneNumber string         `gorm:"type:varchar(20)" json:"phone_number,omitempty"`
    BackupCodes datatypes.JSON `gorm:"type:jsonb" json:"-"` // Never expose
    CreatedAt   time.Time      `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt   time.Time      `gorm:"autoUpdateTime" json:"updated_at"`

    // Association
    User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (m *MFASettings) BeforeCreate(tx *gorm.DB) error {
    if m.ID == "" {
        m.ID = uuid.New().String()
    }
    return nil
}

func (MFASettings) TableName() string {
    return "mfa_settings"
}
```

### Task 4.3: MFA Repository (GORM)

**File**: `internal/repository/mfa_repository.go`

```go
package repository

import (
    "fmt"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type MFARepository struct {
    db *gorm.DB
}

func NewMFARepository(db *gorm.DB) *MFARepository {
    return &MFARepository{db: db}
}

// Create inserts MFA settings
func (r *MFARepository) Create(mfa *models.MFASettings) error {
    return r.db.Create(mfa).Error
}

// GetByUserID retrieves MFA settings for user
func (r *MFARepository) GetByUserID(userID string) (*models.MFASettings, error) {
    var mfa models.MFASettings
    if err := r.db.Where("user_id = ?", userID).First(&mfa).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("MFA settings not found")
        }
        return nil, err
    }
    return &mfa, nil
}

// Update updates MFA settings
func (r *MFARepository) Update(mfa *models.MFASettings) error {
    return r.db.Save(mfa).Error
}

// Delete removes MFA settings (disable MFA)
func (r *MFARepository) Delete(userID string) error {
    return r.db.Where("user_id = ?", userID).Delete(&models.MFASettings{}).Error
}
```

---

## PHASE 5: OAUTH 2.0 & SOCIAL LOGIN

### Task 5.1: OAuth Client Management

**Migration 000013**: `create_oauth_clients_table.up.sql`

```sql
CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    redirect_uris JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    scopes JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX idx_oauth_clients_tenant ON oauth_clients(tenant_id);
```

### Task 5.2: OAuth GORM Models

**File**: `internal/models/oauth.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "gorm.io/datatypes"
)

type OAuthClient struct {
    ID           string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    ClientID     string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"client_id"`
    ClientSecret string         `gorm:"type:varchar(255);not null" json:"-"`
    Name         string         `gorm:"type:varchar(255);not null" json:"name"`
    TenantID     string         `gorm:"type:uuid;index" json:"tenant_id"`
    RedirectURIs datatypes.JSON `gorm:"type:jsonb;not null" json:"redirect_uris"`
    GrantTypes   datatypes.JSON `gorm:"type:jsonb;not null" json:"grant_types"`
    Scopes       datatypes.JSON `gorm:"type:jsonb" json:"scopes"`
    IsActive     bool           `gorm:"default:true" json:"is_active"`
    CreatedAt    time.Time      `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt    time.Time      `gorm:"autoUpdateTime" json:"updated_at"`

    // Association
    Tenant Tenant `gorm:"foreignKey:TenantID" json:"-"`
}

func (o *OAuthClient) BeforeCreate(tx *gorm.DB) error {
    if o.ID == "" {
        o.ID = uuid.New().String()
    }
    return nil
}

func (OAuthClient) TableName() string {
    return "oauth_clients"
}

type RegisterOAuthClientRequest struct {
    Name         string   `json:"name" binding:"required"`
    RedirectURIs []string `json:"redirect_uris" binding:"required"`
    GrantTypes   []string `json:"grant_types" binding:"required"`
    Scopes       []string `json:"scopes"`
}
```

### Task 5.3: Social Login Provider Models

**File**: `internal/models/social_account.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type SocialAccount struct {
    ID           string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    UserID       string    `gorm:"type:uuid;not null;index" json:"user_id"`
    Provider     string    `gorm:"type:varchar(50);not null" json:"provider"` // 'google', 'github'
    ProviderID   string    `gorm:"type:varchar(255);not null" json:"provider_id"`
    Email        string    `gorm:"type:varchar(255)" json:"email"`
    AccessToken  string    `gorm:"type:text" json:"-"`
    RefreshToken string    `gorm:"type:text" json:"-"`
    ExpiresAt    *time.Time `gorm:"type:timestamp" json:"-"`
    CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`

    // Association
    User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (s *SocialAccount) BeforeCreate(tx *gorm.DB) error {
    if s.ID == "" {
        s.ID = uuid.New().String()
    }
    return nil
}

func (SocialAccount) TableName() string {
    return "social_accounts"
}

// Composite unique index: provider + provider_id
func (SocialAccount) GormIndexes() []string {
    return []string{"idx_social_accounts_provider:provider,provider_id,unique"}
}
```

---

## PHASE 6: DYNAMIC RESOURCE REGISTRATION

### Task 6.1: Resource Type Management

**Migration 000014**: `enhance_resource_types_table.up.sql`

```sql
-- Already created in Phase 1, now add tenant support
ALTER TABLE resource_types ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE resource_types ADD COLUMN is_system BOOLEAN DEFAULT false;
ALTER TABLE resource_types ADD COLUMN schema JSONB;

CREATE INDEX idx_resource_types_tenant ON resource_types(tenant_id);

-- System resources are global (null tenant_id)
UPDATE resource_types SET is_system = true WHERE name IN ('user', 'profile', 'task');
```

### Task 6.2: Resource Type GORM Model

**File**: `internal/models/resource_type.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "gorm.io/datatypes"
)

type ResourceType struct {
    ID          string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    Name        string         `gorm:"type:varchar(100);not null" json:"name"`
    Description string         `gorm:"type:text" json:"description"`
    TenantID    *string        `gorm:"type:uuid;index" json:"tenant_id,omitempty"` // NULL for global
    IsSystem    bool           `gorm:"default:false" json:"is_system"` // System resources
    Schema      datatypes.JSON `gorm:"type:jsonb" json:"schema,omitempty"` // Resource attributes
    CreatedAt   time.Time      `gorm:"autoCreateTime" json:"created_at"`
    UpdatedAt   time.Time      `gorm:"autoUpdateTime" json:"updated_at"`

    // Associations
    Tenant      *Tenant       `gorm:"foreignKey:TenantID" json:"-"`
    Permissions []Permission  `gorm:"foreignKey:ResourceTypeID;constraint:OnDelete:CASCADE" json:"-"`
}

func (r *ResourceType) BeforeCreate(tx *gorm.DB) error {
    if r.ID == "" {
        r.ID = uuid.New().String()
    }
    return nil
}

func (ResourceType) TableName() string {
    return "resource_types"
}

type RegisterResourceRequest struct {
    Name        string                 `json:"name" binding:"required"`
    Description string                 `json:"description"`
    Actions     []string               `json:"actions" binding:"required"`
    Schema      map[string]interface{} `json:"schema"`
}
```

### Task 6.3: Resource Registration Service

**File**: `internal/services/resource_service.go`

```go
package services

import (
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/utils"
)

type ResourceService struct {
    resourceRepo *repository.ResourceTypeRepository
    permRepo     *repository.PermissionRepository
    db           *gorm.DB
}

func NewResourceService(
    resourceRepo *repository.ResourceTypeRepository,
    permRepo *repository.PermissionRepository,
    db *gorm.DB,
) *ResourceService {
    return &ResourceService{
        resourceRepo: resourceRepo,
        permRepo:     permRepo,
        db:           db,
    }
}

// RegisterResource allows external apps to register custom resource types
func (s *ResourceService) RegisterResource(tenantID string, req models.RegisterResourceRequest) (*models.ResourceType, error) {
    var resourceType *models.ResourceType

    // Use GORM transaction
    err := s.db.Transaction(func(tx *gorm.DB) error {
        // 1. Create resource type
        resourceType = &models.ResourceType{
            Name:        req.Name,
            Description: req.Description,
            TenantID:    &tenantID,
            IsSystem:    false,
        }
        if err := tx.Create(resourceType).Error; err != nil {
            return utils.InternalServerError("failed to create resource type")
        }

        // 2. Create permissions for each action
        for _, action := range req.Actions {
            permission := &models.Permission{
                Resource:    req.Name,
                Action:      action,
                Description: fmt.Sprintf("%s action on %s", action, req.Name),
                TenantID:    &tenantID,
            }
            if err := tx.Create(permission).Error; err != nil {
                return err
            }
        }

        return nil
    })

    return resourceType, err
}
```

---

## PHASE 7: SDK DEVELOPMENT

### Task 7.1: Go SDK Client

**File**: `pkg/iamsdk/client.go`

```go
package iamsdk

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type Client struct {
    baseURL    string
    apiKey     string
    tenantID   string
    httpClient *http.Client
}

type Config struct {
    BaseURL  string
    APIKey   string
    TenantID string
    Timeout  time.Duration
}

func NewClient(config Config) *Client {
    if config.Timeout == 0 {
        config.Timeout = 10 * time.Second
    }

    return &Client{
        baseURL:  config.BaseURL,
        apiKey:   config.APIKey,
        tenantID: config.TenantID,
        httpClient: &http.Client{
            Timeout: config.Timeout,
        },
    }
}

// doRequest makes HTTP request with authentication
func (c *Client) doRequest(method, path string, body interface{}, result interface{}) error {
    var reqBody *bytes.Buffer
    if body != nil {
        jsonData, err := json.Marshal(body)
        if err != nil {
            return err
        }
        reqBody = bytes.NewBuffer(jsonData)
    } else {
        reqBody = bytes.NewBuffer(nil)
    }

    req, err := http.NewRequest(method, c.baseURL+path, reqBody)
    if err != nil {
        return err
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+c.apiKey)
    req.Header.Set("X-Tenant-ID", c.tenantID)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        var errResp map[string]interface{}
        json.NewDecoder(resp.Body).Decode(&errResp)
        return fmt.Errorf("API error %d: %v", resp.StatusCode, errResp["error"])
    }

    if result != nil {
        return json.NewDecoder(resp.Body).Decode(result)
    }

    return nil
}
```

**File**: `pkg/iamsdk/auth.go`

```go
package iamsdk

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
    MFACode  string `json:"mfa_code,omitempty"`
}

type LoginResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
    MFARequired  bool   `json:"mfa_required"`
}

// Login authenticates a user
func (c *Client) Login(email, password string) (*LoginResponse, error) {
    req := LoginRequest{
        Email:    email,
        Password: password,
    }

    var resp LoginResponse
    err := c.doRequest("POST", "/v1/auth/login", req, &resp)
    return &resp, err
}

// Register creates a new user
func (c *Client) Register(email, password string) error {
    req := map[string]string{
        "email":    email,
        "password": password,
    }
    return c.doRequest("POST", "/v1/auth/register", req, nil)
}
```

**File**: `pkg/iamsdk/authz.go`

```go
package iamsdk

type CheckPermissionRequest struct {
    UserID     string                 `json:"user_id"`
    Resource   string                 `json:"resource"`
    Action     string                 `json:"action"`
    ResourceID string                 `json:"resource_id,omitempty"`
    Context    map[string]interface{} `json:"context,omitempty"`
}

type CheckPermissionResponse struct {
    Allowed bool   `json:"allowed"`
    Reason  string `json:"reason,omitempty"`
}

// Can checks if user has permission
func (c *Client) Can(userID, permission, resourceID string) (bool, error) {
    parts := strings.Split(permission, ":")
    if len(parts) != 2 {
        return false, fmt.Errorf("permission format should be resource:action")
    }

    req := CheckPermissionRequest{
        UserID:     userID,
        Resource:   parts[0],
        Action:     parts[1],
        ResourceID: resourceID,
    }

    var resp CheckPermissionResponse
    err := c.doRequest("POST", "/v1/authz/check", req, &resp)
    if err != nil {
        return false, err
    }

    return resp.Allowed, nil
}
```

---

## PHASE 8: ADVANCED FEATURES

### Task 8.1: Session Management with Redis

**File**: `internal/models/session.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

type Session struct {
    ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    UserID    string    `gorm:"type:uuid;not null;index" json:"user_id"`
    Token     string    `gorm:"type:varchar(500);uniqueIndex;not null" json:"token"`
    IPAddress string    `gorm:"type:varchar(45)" json:"ip_address"`
    UserAgent string    `gorm:"type:text" json:"user_agent"`
    ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
    CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
    LastUsedAt time.Time `gorm:"autoUpdateTime" json:"last_used_at"`

    // Association
    User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

func (s *Session) BeforeCreate(tx *gorm.DB) error {
    if s.ID == "" {
        s.ID = uuid.New().String()
    }
    return nil
}

func (Session) TableName() string {
    return "sessions"
}
```

### Task 8.2: Audit Logging

**Migration 000015**: `create_audit_logs_table.up.sql`

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    decision VARCHAR(10),
    ip_address VARCHAR(45),
    user_agent TEXT,
    context JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
```

**File**: `internal/models/audit.go`

```go
package models

import (
    "time"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "gorm.io/datatypes"
)

type AuditLog struct {
    ID           string         `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
    TenantID     string         `gorm:"type:uuid;index" json:"tenant_id"`
    UserID       *string        `gorm:"type:uuid;index" json:"user_id,omitempty"`
    Action       string         `gorm:"type:varchar(100);not null" json:"action"`
    ResourceType string         `gorm:"type:varchar(50);index" json:"resource_type,omitempty"`
    ResourceID   *string        `gorm:"type:uuid;index" json:"resource_id,omitempty"`
    Decision     string         `gorm:"type:varchar(10)" json:"decision,omitempty"` // allow/deny
    IPAddress    string         `gorm:"type:varchar(45)" json:"ip_address,omitempty"`
    UserAgent    string         `gorm:"type:text" json:"user_agent,omitempty"`
    Context      datatypes.JSON `gorm:"type:jsonb" json:"context,omitempty"`
    Timestamp    time.Time      `gorm:"autoCreateTime;index" json:"timestamp"`

    // Associations
    Tenant *Tenant `gorm:"foreignKey:TenantID" json:"-"`
    User   *User   `gorm:"foreignKey:UserID" json:"-"`
}

func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
    if a.ID == "" {
        a.ID = uuid.New().String()
    }
    return nil
}

func (AuditLog) TableName() string {
    return "audit_logs"
}
```

---

## PHASE 9: MIGRATION FROM PHASE 1

### Task 9.1: Data Migration Script

**File**: `scripts/migrate_to_phase2.go`

```go
package main

import (
    "log"
    "gorm.io/gorm"
    "github.com/yourusername/iam-authorization-service/config"
    "github.com/yourusername/iam-authorization-service/internal/database"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

func main() {
    // Load config
    cfg, _ := config.Load()

    // Connect to database
    db, _ := database.NewPostgres(cfg.Database)

    // Run migrations 000008-000015
    log.Println("Running Phase 2 migrations...")

    // Create default tenant if not exists
    var count int64
    db.Model(&models.Tenant{}).Count(&count)
    if count == 0 {
        defaultTenant := &models.Tenant{
            Name:      "Default Organization",
            Subdomain: "default",
            Status:    "active",
            Plan:      "free",
        }
        db.Create(defaultTenant)

        // Assign all existing users to default tenant
        db.Model(&models.User{}).Where("tenant_id IS NULL").
            Update("tenant_id", defaultTenant.ID)

        // Assign all existing roles to default tenant
        db.Model(&models.Role{}).Where("tenant_id IS NULL").
            Update("tenant_id", defaultTenant.ID)

        log.Println("Default tenant created and data migrated")
    }

    log.Println("Migration complete")
}
```

---

## GORM-SPECIFIC IMPLEMENTATION PATTERNS

### Pattern 1: Tenant-Scoped Queries

```go
// Use GORM scopes for automatic tenant filtering
func (r *UserRepository) GetAllByTenant(tenantID string) ([]models.User, error) {
    var users []models.User
    err := r.db.Scopes(TenantScope(tenantID)).
        Order("created_at DESC").
        Find(&users).Error
    return users, err
}

// Scope definition
func TenantScope(tenantID string) func(*gorm.DB) *gorm.DB {
    return func(db *gorm.DB) *gorm.DB {
        return db.Where("tenant_id = ?", tenantID)
    }
}
```

### Pattern 2: Complex Associations with Preload

```go
// Load user with all associations
func (r *UserRepository) GetWithAssociations(userID string) (*models.User, error) {
    var user models.User
    err := r.db.
        Preload("Tenant").
        Preload("Roles").
        Preload("Roles.Permissions").
        Preload("MFASettings").
        First(&user, "id = ?", userID).Error
    return &user, err
}
```

### Pattern 3: GORM Transactions for Complex Operations

```go
// Example: Create tenant with all setup in one transaction
err := db.Transaction(func(tx *gorm.DB) error {
    // Create tenant
    if err := tx.Create(&tenant).Error; err != nil {
        return err
    }

    // Create admin user
    if err := tx.Create(&adminUser).Error; err != nil {
        return err
    }

    // Create roles
    if err := tx.Create(&roles).Error; err != nil {
        return err
    }

    // All operations committed together, or rolled back on any error
    return nil
})
```

### Pattern 4: Dynamic Updates with GORM

```go
// Update only non-nil fields
func (r *UserRepository) UpdatePartial(userID string, updates map[string]interface{}) error {
    return r.db.Model(&models.User{}).
        Where("id = ?", userID).
        Updates(updates).Error
}
```

---

## DEVELOPMENT TIMELINE (6-8 WEEKS)

### Weeks 1-2: Multi-Tenant Foundation

- [ ] Run migrations 000008-000009 (tenant tables)
- [ ] Implement Tenant GORM model and repository
- [ ] Implement Tenant service with GORM transactions
- [ ] Add tenant middleware
- [ ] Create GORM scopes for tenant isolation
- [ ] Migrate Phase 1 data to default tenant
- [ ] Test tenant isolation with GORM queries

### Weeks 3-4: Enhanced Authentication

- [ ] Run migrations 000010-000012
- [ ] Implement Email Verification (GORM models, repositories, services)
- [ ] Implement Password Reset (GORM models, repositories, services)
- [ ] Integrate email service (SendGrid/SES)
- [ ] Implement MFA (TOTP with GORM storage)
- [ ] Update login flow for MFA
- [ ] Test all authentication flows

### Weeks 5-6: OAuth & Social Login

- [ ] Run migration 000013 (OAuth clients)
- [ ] Implement OAuth 2.0 server
- [ ] Implement Social Account GORM model
- [ ] Integrate Google OAuth
- [ ] Integrate GitHub OAuth
- [ ] Implement account linking with GORM associations
- [ ] Test OAuth flows

### Weeks 7-8: Platform Features & SDK

- [ ] Run migration 000014-000015
- [ ] Implement dynamic resource registration (GORM)
- [ ] Implement audit logging (GORM)
- [ ] Implement session management
- [ ] Develop Go SDK
- [ ] Develop Node.js SDK
- [ ] Create example applications
- [ ] Write comprehensive documentation

---

## CRITICAL SUCCESS CRITERIA

### Multi-Tenancy with GORM

- [ ] Tenant GORM model with proper associations
- [ ] All repositories use GORM tenant scopes
- [ ] Multiple tenants can coexist with data isolation
- [ ] Subdomain-based tenant resolution works

### Self-Hosted Authentication

- [ ] Email verification using GORM models
- [ ] Password reset using GORM models
- [ ] MFA (TOTP) with GORM storage
- [ ] No dependency on external auth providers
- [ ] All auth data managed with GORM

### OAuth 2.0

- [ ] OAuth clients stored in GORM
- [ ] Authorization code flow working
- [ ] Token exchange working

### Social Login

- [ ] Social accounts linked using GORM associations
- [ ] Google login integration
- [ ] GitHub login integration

### Dynamic Resources

- [ ] External apps can register resources via API
- [ ] Resource types stored with GORM
- [ ] Permissions created dynamically with GORM

### SDK & Integration

- [ ] Go SDK functional
- [ ] Node.js SDK functional
- [ ] Example apps demonstrate usage

---

## KEY GORM ADVANTAGES FOR PHASE 2

1. **Automatic SQL Injection Prevention**: All GORM methods use parameterized queries
2. **Association Management**: Easy many-to-many, foreign keys, preloading
3. **Transaction Support**: Built-in `db.Transaction()` for complex operations
4. **Scopes**: Reusable tenant filtering logic
5. **Hooks**: Automatic UUID generation, timestamps
6. **Type Safety**: Compile-time checking
7. **Migration**: Can use AutoMigrate + golang-migrate
8. **JSON Fields**: Easy JSONB support with datatypes.JSON
9. **Query Building**: Chainable methods for complex queries
10. **Multi-Tenant**: Scopes make tenant isolation clean and DRY

---

## DEPENDENCIES FOR PHASE 2

```go
// go.mod (additions to Phase 1)
require (
    // Phase 1 dependencies
    gorm.io/gorm v1.25.5
    gorm.io/driver/postgres v1.5.4
    github.com/gin-gonic/gin v1.9.1
    github.com/golang-jwt/jwt/v5 v5.2.0
    golang.org/x/crypto v0.17.0
    github.com/google/uuid v1.6.0

    // Phase 2 additions
    gorm.io/datatypes v1.2.0              // For JSONB support
    github.com/sendgrid/sendgrid-go v3.14.0 // Email delivery
    github.com/pquerna/otp v1.4.0          // TOTP for MFA
    github.com/skip2/go-qrcode v0.0.0      // QR codes for MFA
    golang.org/x/oauth2 v0.15.0            // OAuth 2.0
    github.com/go-redis/redis/v8 v8.11.5   // Sessions & rate limiting
)
```

---

## MIGRATION PATH FROM PHASE 1

### Step 1: Add Multi-Tenancy (Non-Breaking)

- Run migrations 000008-000009
- All Phase 1 GORM models enhanced with tenant_id
- Create default tenant with GORM
- Migrate existing data to default tenant using GORM updates
- Phase 1 functionality still works

### Step 2: Add Enhanced Auth (Additive)

- Run migrations 000010-000012
- New GORM models (EmailVerification, PasswordReset, MFASettings)
- New repositories using GORM
- Phase 1 login still works

### Step 3: Add Platform Features

- OAuth clients (GORM models)
- Social accounts (GORM associations)
- Resource registration (GORM)
- All new features, no breaking changes

---

## EXAMPLE GORM USAGE IN PHASE 2

### Example 1: Create Tenant with Full Setup (Transaction)

```go
func (s *TenantService) CreateTenantWithSetup(req CreateTenantRequest) (*models.Tenant, error) {
    var tenant *models.Tenant

    err := s.db.Transaction(func(tx *gorm.DB) error {
        // Create tenant
        tenant = &models.Tenant{
            Name: req.Name,
            Subdomain: req.Subdomain,
        }
        if err := tx.Create(tenant).Error; err != nil {
            return err
        }

        // Create admin user (uses BeforeCreate hook for UUID)
        admin := &models.User{
            Email: req.AdminEmail,
            PasswordHash: hashedPassword,
            TenantID: tenant.ID,
            EmailVerified: true,
        }
        if err := tx.Create(admin).Error; err != nil {
            return err
        }

        // Create roles for tenant
        roles := []models.Role{
            {Name: "user", TenantID: tenant.ID},
            {Name: "admin", TenantID: tenant.ID},
        }
        if err := tx.Create(&roles).Error; err != nil {
            return err
        }

        // Assign admin role (many-to-many association)
        if err := tx.Model(&admin).Association("Roles").Append(&roles[1]); err != nil {
            return err
        }

        return nil
    })

    return tenant, err
}
```

### Example 2: Multi-Tenant Query with Preload

```go
func (r *UserRepository) GetUserWithRolesAndPermissions(userID, tenantID string) (*models.User, error) {
    var user models.User
    err := r.db.
        Scopes(TenantScope(tenantID)).
        Preload("Roles").
        Preload("Roles.Permissions").
        Preload("MFASettings").
        First(&user, "id = ?", userID).Error
    return &user, err
}
```

---

## RESOURCES & DOCUMENTATION

- **GORM Documentation**: https://gorm.io/docs/
- **GORM Associations**: https://gorm.io/docs/associations.html
- **GORM Scopes**: https://gorm.io/docs/scopes.html
- **GORM Transactions**: https://gorm.io/docs/transactions.html
- **GORM Datatypes**: https://github.com/go-gorm/datatypes
- **OAuth 2.0 RFC**: https://datatracker.ietf.org/doc/html/rfc6749
- **TOTP RFC**: https://datatracker.ietf.org/doc/html/rfc6238
- **Multi-Tenancy**: https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/overview

---

_End of Phase 2 Implementation Plan with GORM_

**Note**: All database operations use GORM ORM for SQL injection prevention, type safety, and clean code. The service remains self-hosted without external auth provider dependencies.

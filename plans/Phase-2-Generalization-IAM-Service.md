# Phase 2: Generalization - IAM Authorization Service

## Project Overview

**Project Name**: iam-authorization-service (Phase 2 - Full IAM Platform)  
**Purpose**: Transform Taskify into a complete, self-hosted IAM platform with advanced authentication and multi-tenant authorization  
**Key Difference**: Build authentication features IN-HOUSE (no Firebase/Auth0 dependency) + Multi-tenant architecture  
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
          magic links, account lockout, device management)

AUTHORIZATION:
  Before: RBAC/ABAC for tasks only
  After:  RBAC/ABAC for any resource type + multi-tenant

ARCHITECTURE:
  Before: Monolithic app for tasks
  After:  Platform-as-a-Service for external applications

USE CASE:
  Before: Task management only
  After:  Any application can use for IAM needs
```

---

## Core Principles

### 1. Self-Hosted Authentication (No External Providers)

**Key Decision**: Build all authentication features in-house instead of relying on Firebase/Auth0/Okta.

**Why?**
- Full control over authentication flow
- No vendor lock-in
- Custom security policies
- Cost-effective at scale
- Learning opportunity for enterprise IAM
- Data sovereignty

**What This Means**:
- Implement OAuth 2.0 server ourselves
- Handle social login integration directly (Google/GitHub APIs)
- Build email service integration (SendGrid/SES)
- Implement MFA/2FA from scratch
- Create password reset and email verification flows
- Manage session lifecycle

### 2. Multi-Tenant Architecture

Every resource becomes tenant-scoped:
- Multiple organizations (tenants) can use the same IAM service
- Complete data isolation between tenants
- Each tenant has their own users, roles, permissions, policies
- Tenant admins can manage their own IAM configuration

### 3. Dynamic Resource Registration

External applications can register their resources:
- Apps define their own resource types (orders, invoices, documents)
- Apps define actions for each resource type
- IAM service manages permissions for those resources
- Flexible and extensible

### 4. API-First Design

Everything accessible via REST API:
- Authentication APIs
- Authorization APIs
- Tenant management APIs
- User management APIs
- Resource registration APIs
- SDKs for popular languages (Go, Node.js, Python)

---

## Updated Project Structure

```
iam-authorization-service/
├── cmd/
│   ├── api/
│   │   └── main.go                        # Main API server
│   └── worker/                             # Background jobs
│       └── main.go                         # Email worker, token cleanup
│
├── internal/
│   ├── api/
│   │   ├── router.go                       # Enhanced routing
│   │   ├── middleware.go                   # Tenant, rate limit middleware
│   │   └── server.go                       # Server with graceful shutdown
│   │
│   ├── handlers/
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
│   ├── services/
│   │   ├── auth_service.go                 # Enhanced auth
│   │   ├── oauth_service.go                # OAuth 2.0 logic (NEW)
│   │   ├── social_login_service.go         # Google/GitHub (NEW)
│   │   ├── mfa_service.go                  # TOTP/SMS (NEW)
│   │   ├── email_service.go                # Email delivery (NEW)
│   │   ├── verification_service.go         # Email/phone verify (NEW)
│   │   ├── password_service.go             # Reset flows (NEW)
│   │   ├── authz_service.go                # Multi-tenant authz
│   │   ├── tenant_service.go               # Tenant logic (NEW)
│   │   ├── resource_service.go             # Dynamic resources (NEW)
│   │   ├── session_service.go              # Advanced sessions (NEW)
│   │   ├── audit_service.go                # Audit logging (NEW)
│   │   └── webhook_service.go              # Event webhooks (NEW)
│   │
│   ├── repository/
│   │   ├── user_repository.go              # Multi-tenant
│   │   ├── token_repository.go
│   │   ├── tenant_repository.go            # (NEW)
│   │   ├── oauth_client_repository.go      # (NEW)
│   │   ├── mfa_repository.go               # (NEW)
│   │   ├── verification_repository.go      # (NEW)
│   │   ├── resource_type_repository.go     # Enhanced
│   │   ├── role_repository.go              # Multi-tenant
│   │   ├── permission_repository.go        # Multi-tenant
│   │   ├── policy_repository.go            # Multi-tenant
│   │   ├── session_repository.go           # (NEW)
│   │   ├── audit_repository.go             # (NEW)
│   │   └── webhook_repository.go           # (NEW)
│   │
│   ├── models/
│   │   ├── user.go                         # Enhanced
│   │   ├── tenant.go                       # (NEW)
│   │   ├── oauth.go                        # OAuth models (NEW)
│   │   ├── mfa.go                          # MFA models (NEW)
│   │   ├── verification.go                 # Verification models (NEW)
│   │   ├── session.go                      # Session models (NEW)
│   │   ├── resource_type.go                # Enhanced
│   │   ├── role.go                         # Multi-tenant
│   │   ├── permission.go                   # Multi-tenant
│   │   ├── policy.go
│   │   ├── audit.go                        # (NEW)
│   │   └── webhook.go                      # (NEW)
│   │
│   ├── middleware/
│   │   ├── auth.go                         # Enhanced JWT
│   │   ├── tenant.go                       # Tenant isolation (NEW)
│   │   ├── authorization.go
│   │   ├── rate_limit.go                   # (NEW)
│   │   └── cors.go                         # (NEW)
│   │
│   ├── oauth/                              # OAuth 2.0 implementation (NEW)
│   │   ├── server.go                       # OAuth server
│   │   ├── authorization.go                # Authorization code flow
│   │   ├── token.go                        # Token exchange
│   │   └── grants.go                       # Grant types
│   │
│   ├── mfa/                                # MFA implementation (NEW)
│   │   ├── totp.go                         # Time-based OTP
│   │   ├── sms.go                          # SMS OTP
│   │   └── backup_codes.go                 # Backup codes
│   │
│   ├── providers/                          # Social login providers (NEW)
│   │   ├── google.go                       # Google OAuth
│   │   ├── github.go                       # GitHub OAuth
│   │   └── provider.go                     # Provider interface
│   │
│   ├── email/                              # Email service (NEW)
│   │   ├── client.go                       # Email client interface
│   │   ├── sendgrid.go                     # SendGrid implementation
│   │   ├── ses.go                          # AWS SES implementation
│   │   └── templates.go                    # Email templates
│   │
│   ├── workers/                            # Background jobs (NEW)
│   │   ├── email_worker.go                 # Email queue
│   │   ├── token_cleanup_worker.go         # Expired tokens
│   │   └── audit_worker.go                 # Audit log processing
│   │
│   ├── database/
│   │   └── postgres.go
│   │
│   └── utils/
│       ├── jwt.go
│       ├── password.go
│       ├── totp.go                         # TOTP utilities (NEW)
│       ├── crypto.go                       # Encryption (NEW)
│       └── validator.go
│
├── pkg/                                    # Public SDK
│   └── iamsdk/
│       ├── client.go                       # SDK client
│       ├── auth.go                         # Auth methods
│       ├── authz.go                        # Authz methods
│       ├── tenant.go                       # Tenant methods
│       └── examples/                       # Usage examples
│
├── database-migrations/
│   └── migrations/                         # Enhanced schema
│
├── config/
│   ├── config.go
│   └── config.yaml                         # Enhanced config
│
├── scripts/
│   ├── seed.sql
│   ├── create_tenant.sh                    # (NEW)
│   └── run-workers.sh                      # (NEW)
│
├── docs/
│   ├── api/
│   │   └── swagger.yaml                    # Full API docs
│   ├── guides/
│   │   ├── getting-started.md
│   │   ├── multi-tenancy.md
│   │   ├── oauth-setup.md
│   │   └── sdk-usage.md
│   └── architecture.md
│
├── examples/                               # Example integrations
│   ├── ecommerce-app/                      # E-commerce using IAM
│   ├── hr-system/                          # HR app using IAM
│   └── taskify/                            # Taskify as client app
│
├── web/                                    # Admin dashboard (optional)
│   ├── src/
│   ├── public/
│   └── package.json
│
├── docker-compose.yml                      # Multi-service setup
├── Dockerfile
├── .env.example                            # Enhanced env vars
├── Makefile
└── README.md
```

---

## PHASE 1: MULTI-TENANT FOUNDATION

### Task 1.1: Multi-Tenant Database Schema

**Goal**: Add tenant isolation to all existing tables

**Migration 000008**: `create_tenants_table`

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

**Migration 000009**: `add_tenant_id_to_existing_tables`

```sql
-- Add tenant_id to users table
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_users_tenant ON users(tenant_id);

-- Add tenant_id to roles table
ALTER TABLE roles ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_roles_tenant ON roles(tenant_id);

-- Add tenant_id to permissions table (keep some global)
ALTER TABLE permissions ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE permissions ADD COLUMN is_global BOOLEAN DEFAULT false;
CREATE INDEX idx_permissions_tenant ON permissions(tenant_id);

-- Add tenant_id to resource_types (for dynamic registration)
ALTER TABLE resource_types ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_resource_types_tenant ON resource_types(tenant_id);

-- Add tenant_id to policies
ALTER TABLE policies ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_policies_tenant ON policies(tenant_id);

-- Add tenant_id to tasks (demo app)
ALTER TABLE tasks ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_tasks_tenant ON tasks(tenant_id);

-- Create default tenant for existing data
INSERT INTO tenants (name, subdomain, status) VALUES ('Default', 'default', 'active');
UPDATE users SET tenant_id = (SELECT id FROM tenants WHERE subdomain = 'default');
UPDATE roles SET tenant_id = (SELECT id FROM tenants WHERE subdomain = 'default');
UPDATE tasks SET tenant_id = (SELECT id FROM tenants WHERE subdomain = 'default');
```

### Task 1.2: Tenant Management

**File**: `internal/models/tenant.go`

```go
package models

import "time"

type Tenant struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Subdomain string                 `json:"subdomain"`
    Status    string                 `json:"status"`
    Plan      string                 `json:"plan"`
    Settings  map[string]interface{} `json:"settings"`
    CreatedAt time.Time              `json:"created_at"`
    UpdatedAt time.Time              `json:"updated_at"`
}

type CreateTenantRequest struct {
    Name      string                 `json:"name" binding:"required"`
    Subdomain string                 `json:"subdomain" binding:"required"`
    AdminEmail string                `json:"admin_email" binding:"required"`
    Plan      string                 `json:"plan"`
    Settings  map[string]interface{} `json:"settings"`
}

type UpdateTenantRequest struct {
    Name     *string                `json:"name,omitempty"`
    Status   *string                `json:"status,omitempty"`
    Plan     *string                `json:"plan,omitempty"`
    Settings map[string]interface{} `json:"settings,omitempty"`
}
```

**File**: `internal/repository/tenant_repository.go`

```go
package repository

import (
    "database/sql"
    "encoding/json"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type TenantRepository struct {
    db *sql.DB
}

func NewTenantRepository(db *sql.DB) *TenantRepository {
    return &TenantRepository{db: db}
}

func (r *TenantRepository) Create(tenant *models.Tenant) error {
    settingsJSON, _ := json.Marshal(tenant.Settings)
    query := `
        INSERT INTO tenants (name, subdomain, status, plan, settings)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, created_at, updated_at
    `
    return r.db.QueryRow(query, tenant.Name, tenant.Subdomain, tenant.Status, tenant.Plan, settingsJSON).
        Scan(&tenant.ID, &tenant.CreatedAt, &tenant.UpdatedAt)
}

func (r *TenantRepository) GetByID(id string) (*models.Tenant, error) {
    // Implementation with tenant data
}

func (r *TenantRepository) GetBySubdomain(subdomain string) (*models.Tenant, error) {
    // Implementation
}

func (r *TenantRepository) Update(tenant *models.Tenant) error {
    // Implementation
}

func (r *TenantRepository) Delete(id string) error {
    // Soft delete
}
```

**File**: `internal/services/tenant_service.go`

```go
package services

import (
    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/utils"
)

type TenantService struct {
    tenantRepo *repository.TenantRepository
    userRepo   *repository.UserRepository
    roleRepo   *repository.RoleRepository
}

func NewTenantService(tenantRepo *repository.TenantRepository, userRepo *repository.UserRepository, roleRepo *repository.RoleRepository) *TenantService {
    return &TenantService{
        tenantRepo: tenantRepo,
        userRepo:   userRepo,
        roleRepo:   roleRepo,
    }
}

// CreateTenant creates a new tenant with admin user and default roles
func (s *TenantService) CreateTenant(req models.CreateTenantRequest) (*models.Tenant, error) {
    // 1. Validate subdomain uniqueness
    // 2. Create tenant
    // 3. Create admin user for tenant
    // 4. Create default roles (user, admin) for tenant
    // 5. Assign admin role to admin user
    // 6. Return tenant
}

// GetTenant retrieves tenant by ID
func (s *TenantService) GetTenant(tenantID string) (*models.Tenant, error) {
    return s.tenantRepo.GetByID(tenantID)
}

// UpdateTenant updates tenant settings
func (s *TenantService) UpdateTenant(tenantID string, req models.UpdateTenantRequest) (*models.Tenant, error) {
    // Implementation
}

// DeleteTenant soft deletes a tenant
func (s *TenantService) DeleteTenant(tenantID string) error {
    // Implementation
}
```

### Task 1.3: Tenant Isolation Middleware

**File**: `internal/middleware/tenant.go`

```go
package middleware

import (
    "github.com/gin-gonic/gin"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "net/http"
    "strings"
)

type TenantMiddleware struct {
    tenantRepo *repository.TenantRepository
}

func NewTenantMiddleware(tenantRepo *repository.TenantRepository) *TenantMiddleware {
    return &TenantMiddleware{tenantRepo: tenantRepo}
}

// ResolveTenant extracts tenant from subdomain or header
func (m *TenantMiddleware) ResolveTenant() gin.HandlerFunc {
    return func(c *gin.Context) {
        var tenantID string

        // Option 1: Extract from subdomain (tenant.yourapi.com)
        host := c.Request.Host
        parts := strings.Split(host, ".")
        if len(parts) > 2 {
            subdomain := parts[0]
            tenant, err := m.tenantRepo.GetBySubdomain(subdomain)
            if err == nil {
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

        // Set tenant in context for downstream handlers
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

---

## PHASE 2: ENHANCED AUTHENTICATION MODULE

### Task 2.1: Email Verification System

**Migration 000010**: `create_email_verifications_table`

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

-- Add email_verified flag to users
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP;
```

**File**: `internal/models/verification.go`

```go
package models

import "time"

type EmailVerification struct {
    ID         string     `json:"id"`
    UserID     string     `json:"user_id"`
    Email      string     `json:"email"`
    Token      string     `json:"token"`
    ExpiresAt  time.Time  `json:"expires_at"`
    VerifiedAt *time.Time `json:"verified_at,omitempty"`
    CreatedAt  time.Time  `json:"created_at"`
}

type SendVerificationRequest struct {
    Email string `json:"email" binding:"required,email"`
}

type VerifyEmailRequest struct {
    Token string `json:"token" binding:"required"`
}
```

**File**: `internal/services/verification_service.go`

```go
package services

import (
    "crypto/rand"
    "encoding/base64"
    "time"

    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
)

type VerificationService struct {
    verificationRepo *repository.VerificationRepository
    userRepo         *repository.UserRepository
    emailService     *EmailService
}

func NewVerificationService(verificationRepo *repository.VerificationRepository, userRepo *repository.UserRepository, emailService *EmailService) *VerificationService {
    return &VerificationService{
        verificationRepo: verificationRepo,
        userRepo:         userRepo,
        emailService:     emailService,
    }
}

// SendVerificationEmail sends verification email to user
func (s *VerificationService) SendVerificationEmail(userID, email string) error {
    // 1. Generate secure random token
    token, err := s.generateToken()
    if err != nil {
        return err
    }

    // 2. Create verification record (expires in 24 hours)
    verification := &models.EmailVerification{
        UserID:    userID,
        Email:     email,
        Token:     token,
        ExpiresAt: time.Now().Add(24 * time.Hour),
    }

    if err := s.verificationRepo.Create(verification); err != nil {
        return err
    }

    // 3. Send email with verification link
    verificationLink := fmt.Sprintf("https://yourapi.com/v1/auth/verify-email?token=%s", token)
    return s.emailService.SendVerificationEmail(email, verificationLink)
}

// VerifyEmail verifies user email with token
func (s *VerificationService) VerifyEmail(token string) error {
    // 1. Get verification record
    verification, err := s.verificationRepo.GetByToken(token)
    if err != nil {
        return utils.ValidationError("invalid verification token")
    }

    // 2. Check if already verified
    if verification.VerifiedAt != nil {
        return utils.ValidationError("email already verified")
    }

    // 3. Check if expired
    if time.Now().After(verification.ExpiresAt) {
        return utils.ValidationError("verification token expired")
    }

    // 4. Mark as verified
    now := time.Now()
    verification.VerifiedAt = &now
    if err := s.verificationRepo.Update(verification); err != nil {
        return err
    }

    // 5. Update user email_verified flag
    return s.userRepo.MarkEmailVerified(verification.UserID)
}

func (s *VerificationService) generateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

### Task 2.2: Password Reset System

**Migration 000011**: `create_password_resets_table`

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

**File**: `internal/models/password_reset.go`

```go
package models

import "time"

type PasswordReset struct {
    ID        string     `json:"id"`
    UserID    string     `json:"user_id"`
    Token     string     `json:"token"`
    ExpiresAt time.Time  `json:"expires_at"`
    UsedAt    *time.Time `json:"used_at,omitempty"`
    CreatedAt time.Time  `json:"created_at"`
}

type ForgotPasswordRequest struct {
    Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
    Token       string `json:"token" binding:"required"`
    NewPassword string `json:"new_password" binding:"required,min=8"`
}
```

**File**: `internal/services/password_service.go`

```go
package services

import (
    "crypto/rand"
    "encoding/base64"
    "time"

    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/utils"
)

type PasswordService struct {
    passwordResetRepo *repository.PasswordResetRepository
    userRepo          *repository.UserRepository
    emailService      *EmailService
}

func NewPasswordService(passwordResetRepo *repository.PasswordResetRepository, userRepo *repository.UserRepository, emailService *EmailService) *PasswordService {
    return &PasswordService{
        passwordResetRepo: passwordResetRepo,
        userRepo:          userRepo,
        emailService:      emailService,
    }
}

// SendPasswordResetEmail sends password reset link
func (s *PasswordService) SendPasswordResetEmail(email string) error {
    // 1. Get user by email
    user, err := s.userRepo.GetByEmail(email)
    if err != nil {
        // Don't reveal if email exists
        return nil
    }

    // 2. Generate reset token
    token, err := s.generateToken()
    if err != nil {
        return err
    }

    // 3. Create reset record (expires in 1 hour)
    reset := &models.PasswordReset{
        UserID:    user.ID,
        Token:     token,
        ExpiresAt: time.Now().Add(1 * time.Hour),
    }

    if err := s.passwordResetRepo.Create(reset); err != nil {
        return err
    }

    // 4. Send email with reset link
    resetLink := fmt.Sprintf("https://yourapi.com/reset-password?token=%s", token)
    return s.emailService.SendPasswordResetEmail(email, resetLink)
}

// ResetPassword resets user password with token
func (s *PasswordService) ResetPassword(token, newPassword string) error {
    // 1. Get reset record
    reset, err := s.passwordResetRepo.GetByToken(token)
    if err != nil {
        return utils.ValidationError("invalid reset token")
    }

    // 2. Check if already used
    if reset.UsedAt != nil {
        return utils.ValidationError("reset token already used")
    }

    // 3. Check if expired
    if time.Now().After(reset.ExpiresAt) {
        return utils.ValidationError("reset token expired")
    }

    // 4. Validate new password
    if err := utils.ValidatePassword(newPassword); err != nil {
        return err
    }

    // 5. Hash new password
    hashedPassword, err := utils.HashPassword(newPassword)
    if err != nil {
        return err
    }

    // 6. Update user password
    if err := s.userRepo.UpdatePassword(reset.UserID, hashedPassword); err != nil {
        return err
    }

    // 7. Mark token as used
    now := time.Now()
    reset.UsedAt = &now
    return s.passwordResetRepo.Update(reset)
}

func (s *PasswordService) generateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

### Task 2.3: Email Service Integration

**File**: `internal/email/client.go`

```go
package email

// EmailClient interface for sending emails
type EmailClient interface {
    Send(to, subject, body string) error
    SendTemplate(to, templateID string, data map[string]interface{}) error
}

type EmailConfig struct {
    Provider string // "sendgrid", "ses", "smtp"
    APIKey   string
    From     string
    FromName string
}
```

**File**: `internal/email/sendgrid.go`

```go
package email

import (
    "github.com/sendgrid/sendgrid-go"
    "github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendGridClient struct {
    apiKey   string
    from     string
    fromName string
}

func NewSendGridClient(apiKey, from, fromName string) *SendGridClient {
    return &SendGridClient{
        apiKey:   apiKey,
        from:     from,
        fromName: fromName,
    }
}

func (c *SendGridClient) Send(to, subject, body string) error {
    from := mail.NewEmail(c.fromName, c.from)
    toEmail := mail.NewEmail("", to)
    message := mail.NewSingleEmail(from, subject, toEmail, body, body)
    
    client := sendgrid.NewSendClient(c.apiKey)
    _, err := client.Send(message)
    return err
}

func (c *SendGridClient) SendTemplate(to, templateID string, data map[string]interface{}) error {
    // Implementation for dynamic templates
}
```

**File**: `internal/email/templates.go`

```go
package email

const (
    VerificationEmailTemplate = `
        <h1>Verify Your Email</h1>
        <p>Click the link below to verify your email address:</p>
        <a href="{{.VerificationLink}}">Verify Email</a>
        <p>This link expires in 24 hours.</p>
    `

    PasswordResetEmailTemplate = `
        <h1>Reset Your Password</h1>
        <p>Click the link below to reset your password:</p>
        <a href="{{.ResetLink}}">Reset Password</a>
        <p>This link expires in 1 hour.</p>
    `

    WelcomeEmailTemplate = `
        <h1>Welcome to {{.TenantName}}!</h1>
        <p>Your account has been created successfully.</p>
    `
)
```

**File**: `internal/services/email_service.go`

```go
package services

import (
    "bytes"
    "html/template"

    "github.com/yourusername/iam-authorization-service/internal/email"
)

type EmailService struct {
    client email.EmailClient
}

func NewEmailService(client email.EmailClient) *EmailService {
    return &EmailService{client: client}
}

func (s *EmailService) SendVerificationEmail(to, verificationLink string) error {
    subject := "Verify Your Email Address"
    body, err := s.renderTemplate(email.VerificationEmailTemplate, map[string]interface{}{
        "VerificationLink": verificationLink,
    })
    if err != nil {
        return err
    }
    return s.client.Send(to, subject, body)
}

func (s *EmailService) SendPasswordResetEmail(to, resetLink string) error {
    subject := "Reset Your Password"
    body, err := s.renderTemplate(email.PasswordResetEmailTemplate, map[string]interface{}{
        "ResetLink": resetLink,
    })
    if err != nil {
        return err
    }
    return s.client.Send(to, subject, body)
}

func (s *EmailService) SendWelcomeEmail(to, tenantName string) error {
    subject := "Welcome to " + tenantName
    body, err := s.renderTemplate(email.WelcomeEmailTemplate, map[string]interface{}{
        "TenantName": tenantName,
    })
    if err != nil {
        return err
    }
    return s.client.Send(to, subject, body)
}

func (s *EmailService) renderTemplate(tmpl string, data map[string]interface{}) (string, error) {
    t, err := template.New("email").Parse(tmpl)
    if err != nil {
        return "", err
    }

    var buf bytes.Buffer
    if err := t.Execute(&buf, data); err != nil {
        return "", err
    }

    return buf.String(), nil
}
```

---

## PHASE 3: MULTI-FACTOR AUTHENTICATION (MFA)

### Task 3.1: TOTP (Time-Based One-Time Password)

**Migration 000012**: `create_mfa_settings_table`

```sql
CREATE TABLE mfa_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_method VARCHAR(50),  -- 'totp', 'sms'
    totp_secret VARCHAR(255),
    phone_number VARCHAR(20),
    backup_codes JSONB,  -- Array of hashed backup codes
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_mfa_settings_user ON mfa_settings(user_id);
```

**File**: `internal/utils/totp.go`

```go
package utils

import (
    "crypto/rand"
    "encoding/base32"
    "fmt"

    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret generates a new TOTP secret
func GenerateTOTPSecret(issuer, accountName string) (string, string, error) {
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      issuer,
        AccountName: accountName,
    })
    if err != nil {
        return "", "", err
    }

    secret := key.Secret()
    qrCode := key.URL()  // For QR code generation

    return secret, qrCode, nil
}

// ValidateTOTP validates a TOTP code
func ValidateTOTP(secret, code string) bool {
    return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes for MFA
func GenerateBackupCodes(count int) ([]string, error) {
    codes := make([]string, count)
    for i := 0; i < count; i++ {
        b := make([]byte, 8)
        if _, err := rand.Read(b); err != nil {
            return nil, err
        }
        codes[i] = base32.StdEncoding.EncodeToString(b)
    }
    return codes, nil
}
```

**File**: `internal/models/mfa.go`

```go
package models

import "time"

type MFASettings struct {
    ID           string    `json:"id"`
    UserID       string    `json:"user_id"`
    MFAEnabled   bool      `json:"mfa_enabled"`
    MFAMethod    string    `json:"mfa_method"`
    TOTPSecret   string    `json:"-"` // Never expose
    PhoneNumber  string    `json:"phone_number,omitempty"`
    BackupCodes  []string  `json:"-"` // Never expose
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

type EnableMFARequest struct {
    Method string `json:"method" binding:"required"` // "totp" or "sms"
}

type EnableMFAResponse struct {
    Secret    string   `json:"secret"`
    QRCode    string   `json:"qr_code"`
    BackupCodes []string `json:"backup_codes"`
}

type VerifyMFARequest struct {
    Code string `json:"code" binding:"required"`
}

type MFALoginRequest struct {
    Email    string `json:"email" binding:"required"`
    Password string `json:"password" binding:"required"`
    MFACode  string `json:"mfa_code,omitempty"`
}
```

**File**: `internal/services/mfa_service.go`

```go
package services

import (
    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
    "github.com/yourusername/iam-authorization-service/internal/utils"
)

type MFAService struct {
    mfaRepo *repository.MFARepository
}

func NewMFAService(mfaRepo *repository.MFARepository) *MFAService {
    return &MFAService{mfaRepo: mfaRepo}
}

// EnableMFA starts MFA setup process
func (s *MFAService) EnableMFA(userID, email, method string) (*models.EnableMFAResponse, error) {
    // 1. Generate TOTP secret
    secret, qrCode, err := utils.GenerateTOTPSecret("YourApp", email)
    if err != nil {
        return nil, err
    }

    // 2. Generate backup codes
    backupCodes, err := utils.GenerateBackupCodes(10)
    if err != nil {
        return nil, err
    }

    // 3. Hash backup codes before storing
    hashedBackupCodes := make([]string, len(backupCodes))
    for i, code := range backupCodes {
        hashed, _ := utils.HashPassword(code)
        hashedBackupCodes[i] = hashed
    }

    // 4. Save MFA settings (not enabled yet)
    mfaSettings := &models.MFASettings{
        UserID:      userID,
        MFAEnabled:  false, // Enable after verification
        MFAMethod:   method,
        TOTPSecret:  secret,
        BackupCodes: hashedBackupCodes,
    }

    if err := s.mfaRepo.Create(mfaSettings); err != nil {
        return nil, err
    }

    return &models.EnableMFAResponse{
        Secret:      secret,
        QRCode:      qrCode,
        BackupCodes: backupCodes, // Return plain codes once
    }, nil
}

// VerifyAndEnableMFA verifies initial MFA code and enables MFA
func (s *MFAService) VerifyAndEnableMFA(userID, code string) error {
    // 1. Get MFA settings
    mfaSettings, err := s.mfaRepo.GetByUserID(userID)
    if err != nil {
        return utils.ValidationError("MFA not set up")
    }

    // 2. Validate code
    if !utils.ValidateTOTP(mfaSettings.TOTPSecret, code) {
        return utils.ValidationError("invalid MFA code")
    }

    // 3. Enable MFA
    mfaSettings.MFAEnabled = true
    return s.mfaRepo.Update(mfaSettings)
}

// ValidateMFACode validates MFA code during login
func (s *MFAService) ValidateMFACode(userID, code string) (bool, error) {
    mfaSettings, err := s.mfaRepo.GetByUserID(userID)
    if err != nil || !mfaSettings.MFAEnabled {
        return false, nil
    }

    // Check TOTP code
    if utils.ValidateTOTP(mfaSettings.TOTPSecret, code) {
        return true, nil
    }

    // Check backup codes
    for i, hashedCode := range mfaSettings.BackupCodes {
        if utils.ComparePassword(hashedCode, code) == nil {
            // Remove used backup code
            mfaSettings.BackupCodes = append(mfaSettings.BackupCodes[:i], mfaSettings.BackupCodes[i+1:]...)
            s.mfaRepo.Update(mfaSettings)
            return true, nil
        }
    }

    return false, nil
}

// DisableMFA disables MFA for user
func (s *MFAService) DisableMFA(userID string) error {
    return s.mfaRepo.Delete(userID)
}
```

### Task 3.2: Update Login Flow for MFA

**File**: `internal/services/auth_service.go` (enhance Login method)

```go
// Login with MFA support
func (s *AuthService) Login(email, password, mfaCode string) (*models.TokenPair, bool, error) {
    // 1. Validate credentials
    user, err := s.userRepo.GetByEmail(email)
    if err != nil {
        return nil, false, utils.UnauthorizedError("invalid credentials")
    }

    if err := utils.ComparePassword(user.PasswordHash, password); err != nil {
        return nil, false, utils.UnauthorizedError("invalid credentials")
    }

    // 2. Check if MFA is enabled
    mfaSettings, err := s.mfaRepo.GetByUserID(user.ID)
    if err == nil && mfaSettings.MFAEnabled {
        // MFA is enabled
        if mfaCode == "" {
            // Return special response indicating MFA required
            return nil, true, nil // true = MFA required
        }

        // Validate MFA code
        valid, err := s.mfaService.ValidateMFACode(user.ID, mfaCode)
        if err != nil || !valid {
            return nil, false, utils.UnauthorizedError("invalid MFA code")
        }
    }

    // 3. Generate tokens (same as Phase 1)
    // ...
}
```

---

*Due to length constraints, the plan continues with remaining phases...*

---

## REMAINING PHASES OVERVIEW

### PHASE 4: OAUTH 2.0 SERVER IMPLEMENTATION
- Authorization Code Flow
- Client Credentials Flow  
- Token Exchange
- OAuth client registration
- Consent screens

### PHASE 5: SOCIAL LOGIN INTEGRATION
- Google OAuth integration
- GitHub OAuth integration
- Provider abstraction layer
- Account linking

### PHASE 6: DYNAMIC RESOURCE REGISTRATION
- External apps can register resources
- Resource type management
- Action definitions
- Permission templates

### PHASE 7: SDK DEVELOPMENT
- Go SDK
- Node.js SDK
- Python SDK
- Usage examples

### PHASE 8: ADVANCED FEATURES
- Session management
- Device tracking
- Rate limiting
- Audit logging
- Webhooks
- Admin dashboard (optional)

### PHASE 9: MIGRATION & TESTING
- Migration path from Phase 1
- Data migration scripts
- Integration tests
- Load testing
- Documentation

---

## DEVELOPMENT TIMELINE (6-8 WEEKS)

### Weeks 1-2: Multi-Tenant Foundation
- Multi-tenant database schema
- Tenant management
- Tenant isolation middleware
- Migration from Phase 1

### Weeks 3-4: Enhanced Authentication
- Email verification
- Password reset
- Email service integration
- MFA (TOTP + backup codes)

### Weeks 5-6: OAuth & Social Login
- OAuth 2.0 server
- Google/GitHub integration
- Account linking

### Weeks 7-8: Platform Features & Polish
- Dynamic resource registration
- SDK development
- Advanced features (webhooks, audit, etc.)
- Documentation
- Example applications

---

## CRITICAL SUCCESS CRITERIA

### Multi-Tenancy
- [ ] Complete tenant isolation
- [ ] Multiple tenants can coexist
- [ ] Each tenant has own users/roles/permissions
- [ ] Subdomain-based tenant resolution

### Self-Hosted Authentication
- [ ] Email verification working
- [ ] Password reset flows complete
- [ ] MFA (TOTP) functional
- [ ] No dependency on external auth providers

### OAuth 2.0
- [ ] Authorization code flow implemented
- [ ] Client credentials flow implemented
- [ ] Token exchange working
- [ ] OAuth clients can register

### Social Login
- [ ] Google login integration
- [ ] GitHub login integration
- [ ] Account linking works

### Dynamic Resources
- [ ] External apps can register resources
- [ ] Permissions work for custom resources
- [ ] Multi-tenant resource isolation

### SDK & Integration
- [ ] Go SDK functional
- [ ] Node.js SDK functional
- [ ] Example apps demonstrate usage
- [ ] Clear documentation

### Security
- [ ] All authentication self-hosted
- [ ] Tenant data isolated
- [ ] MFA enforced for admins
- [ ] Audit logging complete
- [ ] Rate limiting implemented

---

## KEY DIFFERENCES FROM PHASE 1

| Aspect | Phase 1 (Taskify) | Phase 2 (IAM Platform) |
|--------|-------------------|------------------------|
| Authentication | Basic email/password + JWT | Full suite: OAuth, MFA, social login, email verification |
| Authorization | RBAC/ABAC for tasks | RBAC/ABAC for any resource type |
| Tenancy | Single tenant | Multi-tenant with isolation |
| External Deps | None | Email service (SendGrid/SES) |
| Use Case | Task management | Platform for any application |
| Scope | Learning project | Production-ready IAM service |
| Deployment | Single app | Service + SDKs |

---

## MIGRATION PATH FROM PHASE 1

### Step 1: Add Multi-Tenancy (No Breaking Changes)
- Run migrations 000008-000009
- Create default tenant
- Migrate existing data to default tenant
- Phase 1 functionality still works

### Step 2: Add Enhanced Auth Features
- Email verification (optional for existing users)
- Password reset (new feature)
- MFA (opt-in for users)
- Phase 1 login still works

### Step 3: Expose New APIs
- OAuth endpoints (new)
- Resource registration (new)
- Tenant management (new)
- Phase 1 APIs unchanged

### Step 4: Optional: Migrate Taskify to Client
- Move task management to separate app
- Use IAM service for authentication/authorization
- Demonstrate platform capabilities

---

## RESOURCES & TOOLS

### Dependencies to Add
```go
// go.mod additions
require (
    github.com/sendgrid/sendgrid-go v3.14.0
    github.com/pquerna/otp v1.4.0
    golang.org/x/oauth2 v0.15.0
    github.com/go-redis/redis/v8 v8.11.5  // For rate limiting
)
```

### External Services
- **Email**: SendGrid or AWS SES
- **Redis**: Session storage, rate limiting
- **PostgreSQL**: Main database (same as Phase 1)

### Documentation
- OAuth 2.0 RFC: https://datatracker.ietf.org/doc/html/rfc6749
- TOTP RFC: https://datatracker.ietf.org/doc/html/rfc6238
- OpenID Connect: https://openid.net/connect/
- Multi-tenancy patterns: https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/overview

---

*End of Phase 2 Implementation Plan*

**Note**: This is a high-level roadmap. Each phase will require detailed implementation with specific code for repositories, services, handlers, and tests. The key principle is building all authentication features in-house without relying on external auth providers, while maintaining the strong authorization foundation from Phase 1.


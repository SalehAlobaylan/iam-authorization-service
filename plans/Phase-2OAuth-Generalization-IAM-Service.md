# Phase 2: Generalization to Full IAM Authorization Service

## Project Overview

**Project Name**: iam-authorization-service (Phase 2 - Generalization)  
**Purpose**: Transform Taskify into a multi-tenant IAM platform with advanced authentication and authorization as a service  
**Foundation**: Built on Phase 1 (Taskify) - reuses RBAC/ABAC engine  
**Target Users**: External applications and developers  
**Duration**: 8-12 weeks (depending on features)

---

## Vision: From Taskify to IAM Platform

### What Changes in Phase 2

```
PHASE 1 (Taskify)                    PHASE 2 (IAM Platform)
─────────────────                    ──────────────────────

Authentication: BASIC              → Authentication: ADVANCED
├─ Email/password only              ├─ OAuth 2.0 (Google, GitHub)
├─ Simple JWT tokens                ├─ MFA/2FA
└─ No email verification            ├─ Email verification
                                     ├─ Password reset flows
                                     ├─ Magic links
                                     └─ Account lockout

Authorization: ADVANCED            → Authorization: MULTI-TENANT
├─ RBAC/ABAC (reuse!)               ├─ RBAC/ABAC (enhanced)
├─ Task-specific                    ├─ Generic for any resource
└─ Single organization              ├─ Multiple tenants
                                     ├─ Dynamic resource registration
                                     └─ Policy templates

Use Case: SPECIFIC                 → Use Case: PLATFORM
├─ Task management only             ├─ Service for any application
└─ Internal use                     ├─ REST API + SDKs
                                     ├─ Webhooks
                                     ├─ External integration
                                     └─ Taskify becomes demo app
```

---

## Phase 2 Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│              IAM Authorization Platform                         │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │           Enhanced Authentication Module             │      │
│  │  ┌────────────────┐  ┌──────────────────────────┐   │      │
│  │  │ OAuth Providers│  │ Security Features        │   │      │
│  │  │ - Google       │  │ - MFA/2FA                │   │      │
│  │  │ - GitHub       │  │ - Email verification     │   │      │
│  │  │ - Custom OIDC  │  │ - Password reset         │   │      │
│  │  └────────────────┘  │ - Magic links            │   │      │
│  │                      │ - Account lockout        │   │      │
│  │                      └──────────────────────────┘   │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │      Multi-Tenant Authorization Engine               │      │
│  │  (Core RBAC/ABAC from Phase 1 - Enhanced)            │      │
│  │  ┌────────────────┐  ┌──────────────────────────┐   │      │
│  │  │ Tenant Manager │  │ Resource Manager         │   │      │
│  │  │ - Isolation    │  │ - Dynamic registration   │   │      │
│  │  │ - Settings     │  │ - Type definitions       │   │      │
│  │  └────────────────┘  │ - Custom actions         │   │      │
│  │                      └──────────────────────────┘   │      │
│  │  ┌────────────────┐  ┌──────────────────────────┐   │      │
│  │  │ Policy Engine  │  │ Permission Engine        │   │      │
│  │  │ - Templates    │  │ - Tenant-scoped          │   │      │
│  │  │ - Versioning   │  │ - Resource-level         │   │      │
│  │  │ - Simulation   │  │ - Delegation             │   │      │
│  │  └────────────────┘  └──────────────────────────┘   │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │         External Integration Layer                    │      │
│  │  ┌────────────────┐  ┌──────────────────────────┐   │      │
│  │  │ REST API       │  │ Client SDKs              │   │      │
│  │  │ - Tenant APIs  │  │ - Go SDK                 │   │      │
│  │  │ - Authz APIs   │  │ - JavaScript/Node.js SDK │   │      │
│  │  │ - Webhook APIs │  │ - Python SDK             │   │      │
│  │  └────────────────┘  └──────────────────────────┘   │      │
│  │  ┌────────────────┐  ┌──────────────────────────┐   │      │
│  │  │ API Keys       │  │ Webhooks                 │   │      │
│  │  │ - Management   │  │ - Event notifications    │   │      │
│  │  │ - Scoping      │  │ - Policy changes         │   │      │
│  │  └────────────────┘  └──────────────────────────┘   │      │
│  └──────────────────────────────────────────────────────┘      │
└────────────────────────────────────────────────────────────────┘
                           │
                           │ External Applications Use Service
                           │
        ┌──────────────────┼──────────────────┬─────────────┐
        ▼                  ▼                  ▼             ▼
   ┌─────────┐       ┌──────────┐      ┌──────────┐  ┌─────────┐
   │E-commerce│      │ HR App   │      │ CRM App  │  │Taskify  │
   │   App    │      │          │      │          │  │ (Demo)  │
   └─────────┘       └──────────┘      └──────────┘  └─────────┘
```

---

## Updated Project Structure for Phase 2

```
iam-authorization-service/
├── cmd/
│   ├── api/
│   │   └── main.go                        # Main API server
│   └── admin-dashboard/
│       └── main.go                        # Admin UI server (optional)
│
├── internal/
│   ├── api/
│   │   ├── router.go
│   │   ├── server.go
│   │   └── middleware.go
│   │
│   ├── authentication/                     # ENHANCED MODULE
│   │   ├── handlers/
│   │   │   ├── auth_handler.go            # Email/password (from Phase 1)
│   │   │   ├── oauth_handler.go           # NEW: OAuth flows
│   │   │   ├── verification_handler.go    # NEW: Email verification
│   │   │   ├── password_reset_handler.go  # NEW: Password reset
│   │   │   ├── mfa_handler.go             # NEW: MFA/2FA
│   │   │   └── magic_link_handler.go      # NEW: Magic links
│   │   ├── services/
│   │   │   ├── auth_service.go            # Enhanced from Phase 1
│   │   │   ├── oauth_service.go           # NEW: OAuth logic
│   │   │   ├── email_service.go           # NEW: Email sending
│   │   │   ├── mfa_service.go             # NEW: MFA logic
│   │   │   └── verification_service.go    # NEW: Verification logic
│   │   ├── providers/
│   │   │   ├── google_provider.go         # NEW: Google OAuth
│   │   │   ├── github_provider.go         # NEW: GitHub OAuth
│   │   │   └── oauth_provider.go          # NEW: Base OAuth interface
│   │   └── repository/
│   │       ├── oauth_repository.go        # NEW: OAuth tokens
│   │       └── verification_repository.go # NEW: Verification codes
│   │
│   ├── authorization/                      # ENHANCED MODULE
│   │   ├── handlers/
│   │   │   ├── authz_handler.go           # From Phase 1 (enhanced)
│   │   │   ├── resource_handler.go        # NEW: Resource registration
│   │   │   ├── policy_handler.go          # NEW: Policy management
│   │   │   └── delegation_handler.go      # NEW: Delegation
│   │   ├── services/
│   │   │   ├── authz_service.go           # From Phase 1 (tenant-aware)
│   │   │   ├── resource_service.go        # NEW: Resource management
│   │   │   ├── policy_service.go          # NEW: Policy templates
│   │   │   └── delegation_service.go      # NEW: Delegation logic
│   │   ├── repository/
│   │   │   ├── permission_repository.go   # Enhanced (tenant-scoped)
│   │   │   ├── policy_repository.go       # Enhanced (versioning)
│   │   │   ├── resource_repository.go     # NEW: Dynamic resources
│   │   │   └── delegation_repository.go   # NEW: Delegations
│   │   └── engine/
│   │       ├── rbac_engine.go             # From Phase 1 (enhanced)
│   │       ├── abac_engine.go             # From Phase 1 (enhanced)
│   │       └── policy_evaluator.go        # Enhanced with templates
│   │
│   ├── tenant/                             # NEW MODULE
│   │   ├── handlers/
│   │   │   └── tenant_handler.go          # Tenant CRUD
│   │   ├── services/
│   │   │   └── tenant_service.go          # Tenant logic
│   │   └── repository/
│   │       └── tenant_repository.go       # Tenant data access
│   │
│   ├── integration/                        # NEW MODULE
│   │   ├── handlers/
│   │   │   ├── webhook_handler.go         # Webhook management
│   │   │   └── api_key_handler.go         # API key management
│   │   ├── services/
│   │   │   ├── webhook_service.go         # Webhook dispatch
│   │   │   └── api_key_service.go         # API key generation
│   │   └── repository/
│   │       ├── webhook_repository.go
│   │       └── api_key_repository.go
│   │
│   ├── models/                             # ENHANCED
│   │   ├── user.go                        # Enhanced with OAuth
│   │   ├── tenant.go                      # NEW
│   │   ├── oauth.go                       # NEW
│   │   ├── mfa.go                         # NEW
│   │   ├── verification.go                # NEW
│   │   ├── resource_type.go               # Enhanced
│   │   ├── webhook.go                     # NEW
│   │   └── api_key.go                     # NEW
│   │
│   ├── middleware/
│   │   ├── auth.go                        # Enhanced (multi-provider)
│   │   ├── authorization.go               # Enhanced (tenant-aware)
│   │   ├── tenant.go                      # NEW: Tenant isolation
│   │   ├── api_key.go                     # NEW: API key validation
│   │   └── rate_limit.go                  # NEW: Per-tenant rate limiting
│   │
│   └── utils/
│       ├── jwt.go                         # Enhanced
│       ├── oauth.go                       # NEW
│       ├── email.go                       # NEW
│       └── crypto.go                      # NEW (MFA, verification)
│
├── pkg/                                    # NEW: Public SDKs
│   ├── sdk-go/
│   │   ├── client.go                      # Go SDK
│   │   ├── auth.go
│   │   ├── authz.go
│   │   └── resources.go
│   ├── sdk-js/
│   │   ├── index.js                       # JavaScript/Node.js SDK
│   │   ├── auth.js
│   │   ├── authz.js
│   │   └── package.json
│   └── sdk-python/
│       ├── __init__.py                    # Python SDK
│       ├── client.py
│       ├── auth.py
│       └── setup.py
│
├── web/                                    # NEW: Admin Dashboard (Optional)
│   ├── frontend/
│   │   ├── src/
│   │   ├── package.json
│   │   └── README.md
│   └── templates/                         # Email templates
│       ├── verification.html
│       ├── password_reset.html
│       └── magic_link.html
│
├── database-migrations/
│   └── migrations/
│       ├── ... (Phase 1 migrations)
│       ├── 000008_create_tenants_table.up.sql       # NEW
│       ├── 000009_add_tenant_id_to_tables.up.sql    # NEW
│       ├── 000010_create_oauth_providers.up.sql     # NEW
│       ├── 000011_create_mfa_table.up.sql           # NEW
│       ├── 000012_create_verification_codes.up.sql  # NEW
│       ├── 000013_create_resource_types.up.sql      # NEW (enhanced)
│       ├── 000014_create_webhooks_table.up.sql      # NEW
│       ├── 000015_create_api_keys_table.up.sql      # NEW
│       └── 000016_create_delegations_table.up.sql   # NEW
│
├── docs/
│   ├── api/
│   │   ├── authentication.md              # API docs
│   │   ├── authorization.md
│   │   ├── tenants.md                     # NEW
│   │   └── webhooks.md                    # NEW
│   ├── sdk/
│   │   ├── go-sdk.md                      # SDK docs
│   │   ├── js-sdk.md
│   │   └── python-sdk.md
│   └── guides/
│       ├── integration-guide.md           # How to integrate
│       ├── multi-tenancy.md
│       └── oauth-setup.md
│
├── examples/                               # NEW: Integration examples
│   ├── go-app-example/
│   ├── node-app-example/
│   └── python-app-example/
│
└── scripts/
    ├── seed-phase2.sql                    # Enhanced seed data
    └── migrate-phase1-to-phase2.sh        # Migration script
```

---

## PHASE 2A: MULTI-TENANCY FOUNDATION (Weeks 1-2)

### Task 2A.1: Tenant Database Schema

**File**: `database-migrations/migrations/000008_create_tenants_table.up.sql`

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(100) UNIQUE,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX idx_tenants_active ON tenants(is_active);
```

**File**: `database-migrations/migrations/000008_create_tenants_table.down.sql`

```sql
DROP INDEX IF EXISTS idx_tenants_active;
DROP INDEX IF EXISTS idx_tenants_subdomain;
DROP TABLE IF EXISTS tenants;
```

### Task 2A.2: Add Tenant ID to Existing Tables

**File**: `database-migrations/migrations/000009_add_tenant_id_to_tables.up.sql`

```sql
-- Add tenant_id to users table
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_users_tenant ON users(tenant_id);

-- Add tenant_id to roles table
ALTER TABLE roles ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_roles_tenant ON roles(tenant_id);

-- Add tenant_id to permissions table
ALTER TABLE permissions ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_permissions_tenant ON permissions(tenant_id);

-- Add tenant_id to policies table
ALTER TABLE policies ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_policies_tenant ON policies(tenant_id);

-- Add tenant_id to tasks table (for demo)
ALTER TABLE tasks ADD COLUMN tenant_id UUID REFERENCES tenants(id);
CREATE INDEX idx_tasks_tenant ON tasks(tenant_id);

-- Update unique constraints to be tenant-scoped
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;
ALTER TABLE roles ADD CONSTRAINT roles_name_tenant_unique UNIQUE (name, tenant_id);

ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_resource_action_key;
ALTER TABLE permissions ADD CONSTRAINT permissions_resource_action_tenant_unique 
    UNIQUE (resource, action, tenant_id);
```

**File**: `database-migrations/migrations/000009_add_tenant_id_to_tables.down.sql`

```sql
ALTER TABLE tasks DROP COLUMN tenant_id;
ALTER TABLE policies DROP COLUMN tenant_id;
ALTER TABLE permissions DROP COLUMN tenant_id;
ALTER TABLE roles DROP COLUMN tenant_id;
ALTER TABLE users DROP COLUMN tenant_id;

-- Restore original constraints
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_tenant_unique;
ALTER TABLE roles ADD CONSTRAINT roles_name_key UNIQUE (name);

ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_resource_action_tenant_unique;
ALTER TABLE permissions ADD CONSTRAINT permissions_resource_action_key UNIQUE (resource, action);
```

### Task 2A.3: Tenant Models

**File**: `internal/models/tenant.go`

```go
package models

import "time"

type Tenant struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Subdomain string                 `json:"subdomain"`
    Settings  map[string]interface{} `json:"settings"`
    IsActive  bool                   `json:"is_active"`
    CreatedAt time.Time              `json:"created_at"`
    UpdatedAt time.Time              `json:"updated_at"`
}

type CreateTenantRequest struct {
    Name      string                 `json:"name" binding:"required"`
    Subdomain string                 `json:"subdomain" binding:"required"`
    Settings  map[string]interface{} `json:"settings"`
}

type UpdateTenantRequest struct {
    Name     *string                `json:"name,omitempty"`
    Settings map[string]interface{} `json:"settings,omitempty"`
    IsActive *bool                  `json:"is_active,omitempty"`
}

type TenantSettings struct {
    MaxUsers            int  `json:"max_users"`
    MaxRoles            int  `json:"max_roles"`
    MFARequired         bool `json:"mfa_required"`
    OAuthEnabled        bool `json:"oauth_enabled"`
    SessionTimeoutHours int  `json:"session_timeout_hours"`
}
```

### Task 2A.4: Tenant Repository

**File**: `internal/tenant/repository/tenant_repository.go`

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
        INSERT INTO tenants (name, subdomain, settings, is_active)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at, updated_at
    `
    return r.db.QueryRow(query, tenant.Name, tenant.Subdomain, settingsJSON, tenant.IsActive).
        Scan(&tenant.ID, &tenant.CreatedAt, &tenant.UpdatedAt)
}

func (r *TenantRepository) GetByID(id string) (*models.Tenant, error) {
    tenant := &models.Tenant{}
    var settingsJSON []byte
    query := `
        SELECT id, name, subdomain, settings, is_active, created_at, updated_at
        FROM tenants
        WHERE id = $1
    `
    err := r.db.QueryRow(query, id).Scan(
        &tenant.ID, &tenant.Name, &tenant.Subdomain, &settingsJSON,
        &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
    )
    if err != nil {
        return nil, err
    }
    json.Unmarshal(settingsJSON, &tenant.Settings)
    return tenant, nil
}

func (r *TenantRepository) GetBySubdomain(subdomain string) (*models.Tenant, error) {
    tenant := &models.Tenant{}
    var settingsJSON []byte
    query := `
        SELECT id, name, subdomain, settings, is_active, created_at, updated_at
        FROM tenants
        WHERE subdomain = $1
    `
    err := r.db.QueryRow(query, subdomain).Scan(
        &tenant.ID, &tenant.Name, &tenant.Subdomain, &settingsJSON,
        &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
    )
    if err != nil {
        return nil, err
    }
    json.Unmarshal(settingsJSON, &tenant.Settings)
    return tenant, nil
}

func (r *TenantRepository) Update(tenant *models.Tenant) error {
    settingsJSON, _ := json.Marshal(tenant.Settings)
    query := `
        UPDATE tenants
        SET name = $1, settings = $2, is_active = $3, updated_at = NOW()
        WHERE id = $4
    `
    _, err := r.db.Exec(query, tenant.Name, settingsJSON, tenant.IsActive, tenant.ID)
    return err
}

func (r *TenantRepository) List() ([]models.Tenant, error) {
    query := `SELECT id, name, subdomain, settings, is_active, created_at, updated_at FROM tenants`
    rows, err := r.db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var tenants []models.Tenant
    for rows.Next() {
        var tenant models.Tenant
        var settingsJSON []byte
        if err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.Subdomain, &settingsJSON,
            &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
            return nil, err
        }
        json.Unmarshal(settingsJSON, &tenant.Settings)
        tenants = append(tenants, tenant)
    }
    return tenants, nil
}
```

### Task 2A.5: Tenant Middleware

**File**: `internal/middleware/tenant.go`

```go
package middleware

import (
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/yourusername/iam-authorization-service/internal/tenant/repository"
)

type TenantMiddleware struct {
    tenantRepo *repository.TenantRepository
}

func NewTenantMiddleware(tenantRepo *repository.TenantRepository) *TenantMiddleware {
    return &TenantMiddleware{tenantRepo: tenantRepo}
}

// ExtractTenant extracts tenant from subdomain or header
func (m *TenantMiddleware) ExtractTenant() gin.HandlerFunc {
    return func(c *gin.Context) {
        var tenantID string

        // Option 1: From subdomain (e.g., acme.yourservice.com)
        host := c.Request.Host
        subdomain := extractSubdomain(host)
        if subdomain != "" && subdomain != "www" && subdomain != "api" {
            tenant, err := m.tenantRepo.GetBySubdomain(subdomain)
            if err == nil && tenant.IsActive {
                tenantID = tenant.ID
                c.Set("tenant_id", tenantID)
                c.Set("tenant", tenant)
            }
        }

        // Option 2: From X-Tenant-ID header
        if tenantID == "" {
            tenantID = c.GetHeader("X-Tenant-ID")
            if tenantID != "" {
                tenant, err := m.tenantRepo.GetByID(tenantID)
                if err == nil && tenant.IsActive {
                    c.Set("tenant_id", tenantID)
                    c.Set("tenant", tenant)
                }
            }
        }

        // Option 3: From JWT claims (after authentication)
        if tenantID == "" {
            tenantID = c.GetString("user_tenant_id")
            if tenantID != "" {
                c.Set("tenant_id", tenantID)
            }
        }

        c.Next()
    }
}

// RequireTenant ensures a tenant context exists
func (m *TenantMiddleware) RequireTenant() gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := c.GetString("tenant_id")
        if tenantID == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
            c.Abort()
            return
        }
        c.Next()
    }
}

func extractSubdomain(host string) string {
    // Remove port if present
    if idx := strings.Index(host, ":"); idx != -1 {
        host = host[:idx]
    }
    
    // Split by dots
    parts := strings.Split(host, ".")
    if len(parts) > 2 {
        return parts[0]
    }
    return ""
}
```

### Task 2A.6: Update Existing Repositories for Multi-Tenancy

**Example**: Enhanced User Repository

**File**: `internal/repository/user_repository.go` (modifications)

```go
// Add tenant filtering to existing methods

func (r *UserRepository) GetByEmail(email string, tenantID string) (*models.User, error) {
    user := &models.User{}
    query := `
        SELECT id, email, password_hash, is_active, tenant_id, created_at, updated_at
        FROM users
        WHERE email = $1 AND tenant_id = $2
    `
    err := r.db.QueryRow(query, email, tenantID).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.IsActive,
        &user.TenantID, &user.CreatedAt, &user.UpdatedAt,
    )
    // ... rest of implementation
}

func (r *UserRepository) ListByTenant(tenantID string) ([]models.User, error) {
    query := `
        SELECT id, email, is_active, tenant_id, created_at, updated_at
        FROM users
        WHERE tenant_id = $1
    `
    rows, err := r.db.Query(query, tenantID)
    // ... rest of implementation
}
```

---

## PHASE 2B: ADVANCED AUTHENTICATION (Weeks 3-5)

### Task 2B.1: OAuth 2.0 Provider Tables

**File**: `database-migrations/migrations/000010_create_oauth_providers.up.sql`

```sql
CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE user_oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_oauth_accounts_user ON user_oauth_accounts(user_id);
```

### Task 2B.2: Email Verification Tables

**File**: `database-migrations/migrations/000012_create_verification_codes.up.sql`

```sql
CREATE TABLE verification_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'email_verification', 'password_reset', 'magic_link'
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_verification_codes_user ON verification_codes(user_id);
CREATE INDEX idx_verification_codes_code ON verification_codes(code);

-- Add email_verified column to users
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP;
```

### Task 2B.3: MFA Tables

**File**: `database-migrations/migrations/000011_create_mfa_table.up.sql`

```sql
CREATE TABLE user_mfa (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(50) NOT NULL, -- 'totp', 'sms', 'email'
    secret VARCHAR(255),
    backup_codes JSONB,
    is_enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE mfa_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    verified BOOLEAN DEFAULT false,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_mfa_sessions_user ON mfa_sessions(user_id);
```

### Task 2B.4: OAuth Service Implementation

**File**: `internal/authentication/services/oauth_service.go`

```go
package services

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"

    "github.com/yourusername/iam-authorization-service/internal/models"
)

type OAuthService struct {
    config OAuthConfig
}

type OAuthConfig struct {
    GoogleClientID     string
    GoogleClientSecret string
    GithubClientID     string
    GithubClientSecret string
    RedirectURL        string
}

type OAuthProvider interface {
    GetAuthURL(state string) string
    ExchangeCode(code string) (*OAuthToken, error)
    GetUserInfo(accessToken string) (*OAuthUserInfo, error)
}

type OAuthToken struct {
    AccessToken  string
    RefreshToken string
    ExpiresIn    int
}

type OAuthUserInfo struct {
    ID       string
    Email    string
    Name     string
    Picture  string
    Provider string
}

// Google OAuth Provider
type GoogleProvider struct {
    clientID     string
    clientSecret string
    redirectURL  string
}

func (p *GoogleProvider) GetAuthURL(state string) string {
    baseURL := "https://accounts.google.com/o/oauth2/v2/auth"
    params := url.Values{
        "client_id":     {p.clientID},
        "redirect_uri":  {p.redirectURL},
        "response_type": {"code"},
        "scope":         {"openid email profile"},
        "state":         {state},
    }
    return baseURL + "?" + params.Encode()
}

func (p *GoogleProvider) ExchangeCode(code string) (*OAuthToken, error) {
    tokenURL := "https://oauth2.googleapis.com/token"
    data := url.Values{
        "client_id":     {p.clientID},
        "client_secret": {p.clientSecret},
        "code":          {code},
        "redirect_uri":  {p.redirectURL},
        "grant_type":    {"authorization_code"},
    }

    resp, err := http.PostForm(tokenURL, data)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var token OAuthToken
    if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
        return nil, err
    }

    return &token, nil
}

func (p *GoogleProvider) GetUserInfo(accessToken string) (*OAuthUserInfo, error) {
    userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
    req, _ := http.NewRequest("GET", userInfoURL, nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var userInfo struct {
        ID      string `json:"id"`
        Email   string `json:"email"`
        Name    string `json:"name"`
        Picture string `json:"picture"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, err
    }

    return &OAuthUserInfo{
        ID:       userInfo.ID,
        Email:    userInfo.Email,
        Name:     userInfo.Name,
        Picture:  userInfo.Picture,
        Provider: "google",
    }, nil
}

// GitHub OAuth Provider (similar implementation)
type GitHubProvider struct {
    clientID     string
    clientSecret string
    redirectURL  string
}

// Implementation similar to GoogleProvider...
```

### Task 2B.5: Email Verification Service

**File**: `internal/authentication/services/verification_service.go`

```go
package services

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
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

func (s *VerificationService) SendEmailVerification(userID, email string) error {
    // Generate verification code
    code, err := generateSecureCode(32)
    if err != nil {
        return err
    }

    // Store verification code
    verification := &models.VerificationCode{
        UserID:    userID,
        Code:      code,
        Type:      "email_verification",
        ExpiresAt: time.Now().Add(24 * time.Hour),
    }

    if err := s.verificationRepo.Create(verification); err != nil {
        return err
    }

    // Send email
    verificationURL := fmt.Sprintf("https://yourservice.com/verify-email?code=%s", code)
    return s.emailService.SendVerificationEmail(email, verificationURL)
}

func (s *VerificationService) VerifyEmail(code string) error {
    // Get verification code
    verification, err := s.verificationRepo.GetByCode(code)
    if err != nil {
        return fmt.Errorf("invalid verification code")
    }

    // Check if expired
    if time.Now().After(verification.ExpiresAt) {
        return fmt.Errorf("verification code expired")
    }

    // Check if already used
    if verification.Used {
        return fmt.Errorf("verification code already used")
    }

    // Mark user as verified
    if err := s.userRepo.MarkEmailVerified(verification.UserID); err != nil {
        return err
    }

    // Mark code as used
    return s.verificationRepo.MarkUsed(verification.ID)
}

func (s *VerificationService) SendPasswordReset(email string) error {
    // Get user
    user, err := s.userRepo.GetByEmail(email, "")
    if err != nil {
        // Don't reveal if user exists
        return nil
    }

    // Generate reset code
    code, err := generateSecureCode(32)
    if err != nil {
        return err
    }

    // Store reset code
    verification := &models.VerificationCode{
        UserID:    user.ID,
        Code:      code,
        Type:      "password_reset",
        ExpiresAt: time.Now().Add(1 * time.Hour), // Short expiry for security
    }

    if err := s.verificationRepo.Create(verification); err != nil {
        return err
    }

    // Send email
    resetURL := fmt.Sprintf("https://yourservice.com/reset-password?code=%s", code)
    return s.emailService.SendPasswordResetEmail(email, resetURL)
}

func generateSecureCode(length int) (string, error) {
    b := make([]byte, length)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

### Task 2B.6: MFA Service

**File**: `internal/authentication/services/mfa_service.go`

```go
package services

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"

    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
)

type MFAService struct {
    mfaRepo *repository.MFARepository
}

func NewMFAService(mfaRepo *repository.MFARepository) *MFAService {
    return &MFAService{mfaRepo: mfaRepo}
}

// EnableTOTP generates a TOTP secret and returns QR code URL
func (s *MFAService) EnableTOTP(userID, email string) (*models.MFASetup, error) {
    // Generate TOTP key
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "IAM Service",
        AccountName: email,
    })
    if err != nil {
        return nil, err
    }

    // Generate backup codes
    backupCodes, err := generateBackupCodes(10)
    if err != nil {
        return nil, err
    }

    // Store MFA configuration
    mfa := &models.UserMFA{
        UserID:      userID,
        Method:      "totp",
        Secret:      key.Secret(),
        BackupCodes: backupCodes,
        IsEnabled:   false, // Will be enabled after verification
    }

    if err := s.mfaRepo.Create(mfa); err != nil {
        return nil, err
    }

    return &models.MFASetup{
        Secret:      key.Secret(),
        QRCodeURL:   key.URL(),
        BackupCodes: backupCodes,
    }, nil
}

// VerifyTOTP verifies a TOTP code and enables MFA
func (s *MFAService) VerifyTOTP(userID, code string) error {
    mfa, err := s.mfaRepo.GetByUserID(userID)
    if err != nil {
        return err
    }

    // Verify code
    valid := totp.Validate(code, mfa.Secret)
    if !valid {
        return fmt.Errorf("invalid MFA code")
    }

    // Enable MFA
    return s.mfaRepo.Enable(userID)
}

// ValidateMFA validates an MFA code during login
func (s *MFAService) ValidateMFA(userID, code string) error {
    mfa, err := s.mfaRepo.GetByUserID(userID)
    if err != nil {
        return err
    }

    if !mfa.IsEnabled {
        return fmt.Errorf("MFA not enabled")
    }

    // Check TOTP code
    if totp.Validate(code, mfa.Secret) {
        return nil
    }

    // Check backup codes
    for i, backupCode := range mfa.BackupCodes {
        if backupCode == code {
            // Remove used backup code
            return s.mfaRepo.RemoveBackupCode(userID, i)
        }
    }

    return fmt.Errorf("invalid MFA code")
}

func generateBackupCodes(count int) ([]string, error) {
    codes := make([]string, count)
    for i := 0; i < count; i++ {
        b := make([]byte, 6)
        if _, err := rand.Read(b); err != nil {
            return nil, err
        }
        codes[i] = base64.StdEncoding.EncodeToString(b)[:8]
    }
    return codes, nil
}
```

---

## PHASE 2C: DYNAMIC RESOURCE REGISTRATION (Week 6)

### Task 2C.1: Enhanced Resource Types Table

**File**: `database-migrations/migrations/000013_create_resource_types.up.sql`

```sql
-- Drop old resource_types table if exists
DROP TABLE IF EXISTS resource_types CASCADE;

CREATE TABLE resource_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    attributes JSONB DEFAULT '[]', -- Array of attribute definitions
    is_system BOOLEAN DEFAULT false, -- System resources can't be deleted
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE resource_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type_id UUID REFERENCES resource_types(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    UNIQUE(resource_type_id, action)
);

CREATE INDEX idx_resource_types_tenant ON resource_types(tenant_id);
CREATE INDEX idx_resource_actions_type ON resource_actions(resource_type_id);
```

### Task 2C.2: Resource Registration Service

**File**: `internal/authorization/services/resource_service.go`

```go
package services

import (
    "fmt"

    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
)

type ResourceService struct {
    resourceRepo *repository.ResourceRepository
}

func NewResourceService(resourceRepo *repository.ResourceRepository) *ResourceService {
    return &ResourceService{resourceRepo: resourceRepo}
}

// RegisterResourceType allows external apps to register their resource types
func (s *ResourceService) RegisterResourceType(tenantID string, req models.RegisterResourceRequest) (*models.ResourceType, error) {
    // Validate request
    if err := validateResourceRequest(req); err != nil {
        return nil, err
    }

    // Create resource type
    resourceType := &models.ResourceType{
        TenantID:    tenantID,
        Name:        req.Name,
        Description: req.Description,
        Attributes:  req.Attributes,
        IsSystem:    false,
    }

    if err := s.resourceRepo.CreateResourceType(resourceType); err != nil {
        return nil, err
    }

    // Create actions for this resource type
    for _, action := range req.Actions {
        resourceAction := &models.ResourceAction{
            ResourceTypeID: resourceType.ID,
            Action:         action.Name,
            Description:    action.Description,
        }
        if err := s.resourceRepo.CreateResourceAction(resourceAction); err != nil {
            return nil, err
        }
    }

    return resourceType, nil
}

// GetResourceTypes returns all resource types for a tenant
func (s *ResourceService) GetResourceTypes(tenantID string) ([]models.ResourceType, error) {
    return s.resourceRepo.ListByTenant(tenantID)
}

// UpdateResourceType updates a resource type
func (s *ResourceService) UpdateResourceType(tenantID, resourceTypeID string, req models.UpdateResourceRequest) error {
    // Get existing resource type
    resourceType, err := s.resourceRepo.GetByID(resourceTypeID)
    if err != nil {
        return err
    }

    // Verify tenant ownership
    if resourceType.TenantID != tenantID {
        return fmt.Errorf("unauthorized")
    }

    // Can't modify system resources
    if resourceType.IsSystem {
        return fmt.Errorf("cannot modify system resource types")
    }

    // Update
    if req.Description != nil {
        resourceType.Description = *req.Description
    }
    if req.Attributes != nil {
        resourceType.Attributes = req.Attributes
    }

    return s.resourceRepo.UpdateResourceType(resourceType)
}

func validateResourceRequest(req models.RegisterResourceRequest) error {
    if req.Name == "" {
        return fmt.Errorf("resource name is required")
    }
    if len(req.Actions) == 0 {
        return fmt.Errorf("at least one action is required")
    }
    return nil
}
```

### Task 2C.3: Resource Registration Models

**File**: `internal/models/resource_type.go` (enhanced)

```go
package models

import "time"

type ResourceType struct {
    ID          string                   `json:"id"`
    TenantID    string                   `json:"tenant_id"`
    Name        string                   `json:"name"`
    Description string                   `json:"description"`
    Attributes  []ResourceAttribute      `json:"attributes"`
    IsSystem    bool                     `json:"is_system"`
    CreatedAt   time.Time                `json:"created_at"`
    UpdatedAt   time.Time                `json:"updated_at"`
}

type ResourceAttribute struct {
    Name        string   `json:"name"`
    Type        string   `json:"type"` // string, number, boolean, enum
    Description string   `json:"description"`
    EnumValues  []string `json:"enum_values,omitempty"`
}

type ResourceAction struct {
    ID             string    `json:"id"`
    ResourceTypeID string    `json:"resource_type_id"`
    Action         string    `json:"action"`
    Description    string    `json:"description"`
}

type RegisterResourceRequest struct {
    Name        string              `json:"name" binding:"required"`
    Description string              `json:"description"`
    Actions     []ActionDefinition  `json:"actions" binding:"required,min=1"`
    Attributes  []ResourceAttribute `json:"attributes"`
}

type ActionDefinition struct {
    Name        string `json:"name" binding:"required"`
    Description string `json:"description"`
}

type UpdateResourceRequest struct {
    Description *string             `json:"description,omitempty"`
    Attributes  []ResourceAttribute `json:"attributes,omitempty"`
}
```

### Task 2C.4: Resource Registration Handler

**File**: `internal/authorization/handlers/resource_handler.go`

```go
package handlers

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/yourusername/iam-authorization-service/internal/authorization/services"
    "github.com/yourusername/iam-authorization-service/internal/models"
)

type ResourceHandler struct {
    resourceService *services.ResourceService
}

func NewResourceHandler(resourceService *services.ResourceService) *ResourceHandler {
    return &ResourceHandler{resourceService: resourceService}
}

// RegisterResource allows external applications to register their resources
func (h *ResourceHandler) RegisterResource(c *gin.Context) {
    tenantID := c.GetString("tenant_id")
    if tenantID == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "tenant context required"})
        return
    }

    var req models.RegisterResourceRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    resourceType, err := h.resourceService.RegisterResourceType(tenantID, req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusCreated, resourceType)
}

// ListResources returns all registered resources for the tenant
func (h *ResourceHandler) ListResources(c *gin.Context) {
    tenantID := c.GetString("tenant_id")

    resources, err := h.resourceService.GetResourceTypes(tenantID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"resources": resources})
}

// UpdateResource updates a resource type
func (h *ResourceHandler) UpdateResource(c *gin.Context) {
    tenantID := c.GetString("tenant_id")
    resourceID := c.Param("id")

    var req models.UpdateResourceRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    if err := h.resourceService.UpdateResourceType(tenantID, resourceID, req); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Resource updated successfully"})
}
```

---

## PHASE 2D: CLIENT SDKs (Week 7)

### Task 2D.1: Go SDK

**File**: `pkg/sdk-go/client.go`

```go
package iamsdkgo

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

type Client struct {
    BaseURL    string
    APIKey     string
    TenantID   string
    HTTPClient *http.Client
}

type ClientConfig struct {
    BaseURL  string
    APIKey   string
    TenantID string
    Timeout  time.Duration
}

func NewClient(config ClientConfig) *Client {
    if config.Timeout == 0 {
        config.Timeout = 10 * time.Second
    }

    return &Client{
        BaseURL:  config.BaseURL,
        APIKey:   config.APIKey,
        TenantID: config.TenantID,
        HTTPClient: &http.Client{
            Timeout: config.Timeout,
        },
    }
}

// Authorization Methods

// Can checks if a user has permission to perform an action on a resource
func (c *Client) Can(userID, permission, resourceID string) (bool, error) {
    parts := splitPermission(permission)
    if len(parts) != 2 {
        return false, fmt.Errorf("invalid permission format: use 'resource:action'")
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

// CanWithContext checks permission with additional context attributes
func (c *Client) CanWithContext(userID, permission, resourceID string, context map[string]interface{}) (bool, error) {
    parts := splitPermission(permission)
    if len(parts) != 2 {
        return false, fmt.Errorf("invalid permission format")
    }

    req := CheckPermissionWithContextRequest{
        UserID:     userID,
        Resource:   parts[0],
        Action:     parts[1],
        ResourceID: resourceID,
        Context:    context,
    }

    var resp CheckPermissionResponse
    err := c.doRequest("POST", "/v1/authz/check-context", req, &resp)
    return resp.Allowed, err
}

// BatchCheck checks multiple permissions at once
func (c *Client) BatchCheck(userID string, checks []PermissionCheck) ([]PermissionResult, error) {
    req := BatchCheckRequest{
        UserID: userID,
        Checks: checks,
    }

    var resp BatchCheckResponse
    err := c.doRequest("POST", "/v1/authz/batch-check", req, &resp)
    return resp.Results, err
}

// Resource Management

// RegisterResource registers a new resource type
func (c *Client) RegisterResource(req RegisterResourceRequest) (*ResourceType, error) {
    var resource ResourceType
    err := c.doRequest("POST", "/v1/resources", req, &resource)
    return &resource, err
}

// GetResources lists all registered resources for the tenant
func (c *Client) GetResources() ([]ResourceType, error) {
    var resp struct {
        Resources []ResourceType `json:"resources"`
    }
    err := c.doRequest("GET", "/v1/resources", nil, &resp)
    return resp.Resources, err
}

// Internal HTTP methods

func (c *Client) doRequest(method, path string, body, result interface{}) error {
    url := c.BaseURL + path

    var bodyReader io.Reader
    if body != nil {
        jsonBody, err := json.Marshal(body)
        if err != nil {
            return err
        }
        bodyReader = bytes.NewBuffer(jsonBody)
    }

    req, err := http.NewRequest(method, url, bodyReader)
    if err != nil {
        return err
    }

    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+c.APIKey)
    req.Header.Set("X-Tenant-ID", c.TenantID)

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        var errResp ErrorResponse
        json.NewDecoder(resp.Body).Decode(&errResp)
        return fmt.Errorf("API error: %s", errResp.Error)
    }

    if result != nil {
        return json.NewDecoder(resp.Body).Decode(result)
    }

    return nil
}

func splitPermission(permission string) []string {
    for i, c := range permission {
        if c == ':' {
            return []string{permission[:i], permission[i+1:]}
        }
    }
    return []string{permission}
}

// Types

type CheckPermissionRequest struct {
    UserID     string `json:"user_id"`
    Resource   string `json:"resource"`
    Action     string `json:"action"`
    ResourceID string `json:"resource_id,omitempty"`
}

type CheckPermissionResponse struct {
    Allowed bool   `json:"allowed"`
    Reason  string `json:"reason,omitempty"`
}

type PermissionCheck struct {
    Resource   string `json:"resource"`
    Action     string `json:"action"`
    ResourceID string `json:"resource_id,omitempty"`
}

type PermissionResult struct {
    Resource   string `json:"resource"`
    Action     string `json:"action"`
    ResourceID string `json:"resource_id,omitempty"`
    Allowed    bool   `json:"allowed"`
}

type BatchCheckRequest struct {
    UserID string            `json:"user_id"`
    Checks []PermissionCheck `json:"checks"`
}

type BatchCheckResponse struct {
    Results []PermissionResult `json:"results"`
}

type ErrorResponse struct {
    Error string `json:"error"`
}
```

### Task 2D.2: JavaScript/Node.js SDK

**File**: `pkg/sdk-js/index.js`

```javascript
const axios = require('axios');

class IAMClient {
  constructor(config) {
    this.baseURL = config.baseURL;
    this.apiKey = config.apiKey;
    this.tenantID = config.tenantID;
    this.timeout = config.timeout || 10000;

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'X-Tenant-ID': this.tenantID
      }
    });
  }

  // Authorization Methods

  /**
   * Check if user has permission
   * @param {string} userId - User ID
   * @param {string} permission - Permission in format 'resource:action'
   * @param {string} resourceId - Resource ID (optional)
   * @returns {Promise<boolean>}
   */
  async can(userId, permission, resourceId = null) {
    const [resource, action] = permission.split(':');
    if (!resource || !action) {
      throw new Error('Invalid permission format. Use "resource:action"');
    }

    const response = await this.client.post('/v1/authz/check', {
      user_id: userId,
      resource: resource,
      action: action,
      resource_id: resourceId
    });

    return response.data.allowed;
  }

  /**
   * Check permission with context
   * @param {string} userId - User ID
   * @param {string} permission - Permission in format 'resource:action'
   * @param {string} resourceId - Resource ID
   * @param {object} context - Additional context attributes
   * @returns {Promise<boolean>}
   */
  async canWithContext(userId, permission, resourceId, context) {
    const [resource, action] = permission.split(':');

    const response = await this.client.post('/v1/authz/check-context', {
      user_id: userId,
      resource: resource,
      action: action,
      resource_id: resourceId,
      context: context
    });

    return response.data.allowed;
  }

  /**
   * Batch check multiple permissions
   * @param {string} userId - User ID
   * @param {Array} checks - Array of {resource, action, resourceId}
   * @returns {Promise<Array>}
   */
  async batchCheck(userId, checks) {
    const response = await this.client.post('/v1/authz/batch-check', {
      user_id: userId,
      checks: checks
    });

    return response.data.results;
  }

  // Resource Management

  /**
   * Register a new resource type
   * @param {object} resource - Resource definition
   * @returns {Promise<object>}
   */
  async registerResource(resource) {
    const response = await this.client.post('/v1/resources', resource);
    return response.data;
  }

  /**
   * Get all registered resources
   * @returns {Promise<Array>}
   */
  async getResources() {
    const response = await this.client.get('/v1/resources');
    return response.data.resources;
  }

  // User Management

  /**
   * Get user permissions
   * @param {string} userId - User ID
   * @returns {Promise<Array>}
   */
  async getUserPermissions(userId) {
    const response = await this.client.get(`/v1/authz/permissions/user/${userId}`);
    return response.data.permissions;
  }

  /**
   * Assign role to user
   * @param {string} userId - User ID
   * @param {string} roleId - Role ID
   * @returns {Promise<object>}
   */
  async assignRole(userId, roleId) {
    const response = await this.client.post(`/v1/users/${userId}/roles`, {
      role_id: roleId
    });
    return response.data;
  }
}

module.exports = IAMClient;
```

**File**: `pkg/sdk-js/package.json`

```json
{
  "name": "@your-org/iam-sdk",
  "version": "1.0.0",
  "description": "JavaScript SDK for IAM Authorization Service",
  "main": "index.js",
  "scripts": {
    "test": "jest"
  },
  "keywords": ["iam", "authorization", "rbac", "abac"],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
```

### Task 2D.3: Python SDK

**File**: `pkg/sdk-python/iam_sdk/__init__.py`

```python
import requests
from typing import List, Dict, Optional, Any

class IAMClient:
    """Client for IAM Authorization Service"""
    
    def __init__(self, base_url: str, api_key: str, tenant_id: str, timeout: int = 10):
        self.base_url = base_url
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'X-Tenant-ID': tenant_id
        })
    
    def can(self, user_id: str, permission: str, resource_id: Optional[str] = None) -> bool:
        """
        Check if user has permission
        
        Args:
            user_id: User ID
            permission: Permission in format 'resource:action'
            resource_id: Optional resource ID
            
        Returns:
            bool: True if allowed, False otherwise
        """
        resource, action = permission.split(':', 1)
        
        response = self.session.post(
            f'{self.base_url}/v1/authz/check',
            json={
                'user_id': user_id,
                'resource': resource,
                'action': action,
                'resource_id': resource_id
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()['allowed']
    
    def can_with_context(
        self, 
        user_id: str, 
        permission: str, 
        resource_id: str,
        context: Dict[str, Any]
    ) -> bool:
        """Check permission with additional context"""
        resource, action = permission.split(':', 1)
        
        response = self.session.post(
            f'{self.base_url}/v1/authz/check-context',
            json={
                'user_id': user_id,
                'resource': resource,
                'action': action,
                'resource_id': resource_id,
                'context': context
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()['allowed']
    
    def batch_check(self, user_id: str, checks: List[Dict]) -> List[Dict]:
        """Batch check multiple permissions"""
        response = self.session.post(
            f'{self.base_url}/v1/authz/batch-check',
            json={
                'user_id': user_id,
                'checks': checks
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()['results']
    
    def register_resource(self, resource: Dict) -> Dict:
        """Register a new resource type"""
        response = self.session.post(
            f'{self.base_url}/v1/resources',
            json=resource,
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()
    
    def get_resources(self) -> List[Dict]:
        """Get all registered resources"""
        response = self.session.get(
            f'{self.base_url}/v1/resources',
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()['resources']
    
    def get_user_permissions(self, user_id: str) -> List[Dict]:
        """Get all permissions for a user"""
        response = self.session.get(
            f'{self.base_url}/v1/authz/permissions/user/{user_id}',
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()['permissions']
```

**File**: `pkg/sdk-python/setup.py`

```python
from setuptools import setup, find_packages

setup(
    name='iam-sdk',
    version='1.0.0',
    description='Python SDK for IAM Authorization Service',
    author='Your Name',
    author_email='your.email@example.com',
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
    ],
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
```

---

## PHASE 2E: WEBHOOKS & API KEYS (Week 8)

### Task 2E.1: Webhooks Database Schema

**File**: `database-migrations/migrations/000014_create_webhooks_table.up.sql`

```sql
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(500) NOT NULL,
    secret VARCHAR(255) NOT NULL,
    events JSONB NOT NULL, -- Array of event types to subscribe to
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(50) NOT NULL, -- 'pending', 'delivered', 'failed'
    status_code INTEGER,
    response_body TEXT,
    attempts INTEGER DEFAULT 0,
    next_retry_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    delivered_at TIMESTAMP
);

CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status);
```

### Task 2E.2: API Keys Database Schema

**File**: `database-migrations/migrations/000015_create_api_keys_table.up.sql`

```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    key_prefix VARCHAR(20) NOT NULL, -- First few chars for identification
    scopes JSONB DEFAULT '[]', -- Array of allowed scopes
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
```

### Task 2E.3: Webhook Service

**File**: `internal/integration/services/webhook_service.go`

```go
package services

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
)

type WebhookService struct {
    webhookRepo *repository.WebhookRepository
    httpClient  *http.Client
}

func NewWebhookService(webhookRepo *repository.WebhookRepository) *WebhookService {
    return &WebhookService{
        webhookRepo: webhookRepo,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// DispatchEvent sends webhook notifications for an event
func (s *WebhookService) DispatchEvent(tenantID, eventType string, payload interface{}) error {
    // Get all active webhooks for this tenant subscribed to this event
    webhooks, err := s.webhookRepo.GetByTenantAndEvent(tenantID, eventType)
    if err != nil {
        return err
    }

    for _, webhook := range webhooks {
        // Create delivery record
        delivery := &models.WebhookDelivery{
            WebhookID: webhook.ID,
            EventType: eventType,
            Payload:   payload,
            Status:    "pending",
            Attempts:  0,
        }

        if err := s.webhookRepo.CreateDelivery(delivery); err != nil {
            continue
        }

        // Send webhook asynchronously
        go s.sendWebhook(webhook, delivery)
    }

    return nil
}

func (s *WebhookService) sendWebhook(webhook *models.Webhook, delivery *models.WebhookDelivery) {
    // Marshal payload
    payloadBytes, err := json.Marshal(delivery.Payload)
    if err != nil {
        s.updateDeliveryFailed(delivery.ID, 0, err.Error())
        return
    }

    // Create HMAC signature
    signature := s.generateSignature(webhook.Secret, payloadBytes)

    // Create HTTP request
    req, err := http.NewRequest("POST", webhook.URL, bytes.NewBuffer(payloadBytes))
    if err != nil {
        s.updateDeliveryFailed(delivery.ID, 0, err.Error())
        return
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Webhook-Signature", signature)
    req.Header.Set("X-Event-Type", delivery.EventType)
    req.Header.Set("X-Delivery-ID", delivery.ID)

    // Send request
    resp, err := s.httpClient.Do(req)
    if err != nil {
        s.updateDeliveryFailed(delivery.ID, 0, err.Error())
        s.scheduleRetry(delivery.ID, delivery.Attempts+1)
        return
    }
    defer resp.Body.Close()

    // Read response body
    var responseBody bytes.Buffer
    responseBody.ReadFrom(resp.Body)

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        s.updateDeliverySuccess(delivery.ID, resp.StatusCode, responseBody.String())
    } else {
        s.updateDeliveryFailed(delivery.ID, resp.StatusCode, responseBody.String())
        s.scheduleRetry(delivery.ID, delivery.Attempts+1)
    }
}

func (s *WebhookService) generateSignature(secret string, payload []byte) string {
    h := hmac.New(sha256.New, []byte(secret))
    h.Write(payload)
    return hex.EncodeToString(h.Sum(nil))
}

func (s *WebhookService) updateDeliverySuccess(deliveryID string, statusCode int, responseBody string) {
    s.webhookRepo.UpdateDeliveryStatus(deliveryID, "delivered", statusCode, responseBody)
}

func (s *WebhookService) updateDeliveryFailed(deliveryID string, statusCode int, responseBody string) {
    s.webhookRepo.UpdateDeliveryStatus(deliveryID, "failed", statusCode, responseBody)
}

func (s *WebhookService) scheduleRetry(deliveryID string, attempt int) {
    // Exponential backoff: 1min, 5min, 15min, 30min, 1hr
    delays := []time.Duration{
        1 * time.Minute,
        5 * time.Minute,
        15 * time.Minute,
        30 * time.Minute,
        1 * time.Hour,
    }

    if attempt >= len(delays) {
        return // Max retries reached
    }

    nextRetry := time.Now().Add(delays[attempt])
    s.webhookRepo.ScheduleRetry(deliveryID, attempt, nextRetry)
}

// Event types that trigger webhooks
const (
    EventUserCreated         = "user.created"
    EventUserDeleted         = "user.deleted"
    EventRoleAssigned        = "role.assigned"
    EventRoleRevoked         = "role.revoked"
    EventPermissionGranted   = "permission.granted"
    EventPermissionRevoked   = "permission.revoked"
    EventPolicyCreated       = "policy.created"
    EventPolicyUpdated       = "policy.updated"
    EventPolicyDeleted       = "policy.deleted"
    EventResourceRegistered  = "resource.registered"
)
```

### Task 2E.4: API Key Service

**File**: `internal/integration/services/api_key_service.go`

```go
package services

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/yourusername/iam-authorization-service/internal/models"
    "github.com/yourusername/iam-authorization-service/internal/repository"
)

type APIKeyService struct {
    apiKeyRepo *repository.APIKeyRepository
}

func NewAPIKeyService(apiKeyRepo *repository.APIKeyRepository) *APIKeyService {
    return &APIKeyService{apiKeyRepo: apiKeyRepo}
}

// GenerateAPIKey creates a new API key for a tenant
func (s *APIKeyService) GenerateAPIKey(tenantID, name string, scopes []string, expiresAt *time.Time) (*models.APIKeyResponse, error) {
    // Generate random key
    keyBytes := make([]byte, 32)
    if _, err := rand.Read(keyBytes); err != nil {
        return nil, err
    }
    
    // Encode as base64
    keyString := base64.URLEncoding.EncodeToString(keyBytes)
    
    // Add prefix for identification (iam_)
    fullKey := fmt.Sprintf("iam_%s", keyString)
    
    // Hash the key for storage
    hash := sha256.Sum256([]byte(fullKey))
    keyHash := hex.EncodeToString(hash[:])
    
    // Store in database
    apiKey := &models.APIKey{
        TenantID:  tenantID,
        Name:      name,
        KeyHash:   keyHash,
        KeyPrefix: fullKey[:12], // Store first 12 chars for identification
        Scopes:    scopes,
        ExpiresAt: expiresAt,
        IsActive:  true,
    }
    
    if err := s.apiKeyRepo.Create(apiKey); err != nil {
        return nil, err
    }
    
    // Return the full key (only shown once!)
    return &models.APIKeyResponse{
        ID:        apiKey.ID,
        Name:      apiKey.Name,
        Key:       fullKey, // Only returned on creation
        KeyPrefix: apiKey.KeyPrefix,
        Scopes:    apiKey.Scopes,
        ExpiresAt: apiKey.ExpiresAt,
        CreatedAt: apiKey.CreatedAt,
    }, nil
}

// ValidateAPIKey validates an API key and returns tenant info
func (s *APIKeyService) ValidateAPIKey(key string) (*models.APIKey, error) {
    // Hash the provided key
    hash := sha256.Sum256([]byte(key))
    keyHash := hex.EncodeToString(hash[:])
    
    // Get API key from database
    apiKey, err := s.apiKeyRepo.GetByHash(keyHash)
    if err != nil {
        return nil, fmt.Errorf("invalid API key")
    }
    
    // Check if active
    if !apiKey.IsActive {
        return nil, fmt.Errorf("API key is inactive")
    }
    
    // Check expiration
    if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
        return nil, fmt.Errorf("API key expired")
    }
    
    // Update last used timestamp
    s.apiKeyRepo.UpdateLastUsed(apiKey.ID)
    
    return apiKey, nil
}

// RevokeAPIKey deactivates an API key
func (s *APIKeyService) RevokeAPIKey(tenantID, keyID string) error {
    // Get key
    apiKey, err := s.apiKeyRepo.GetByID(keyID)
    if err != nil {
        return err
    }
    
    // Verify tenant ownership
    if apiKey.TenantID != tenantID {
        return fmt.Errorf("unauthorized")
    }
    
    return s.apiKeyRepo.Revoke(keyID)
}
```

### Task 2E.5: API Key Middleware

**File**: `internal/middleware/api_key.go`

```go
package middleware

import (
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/yourusername/iam-authorization-service/internal/integration/services"
)

type APIKeyMiddleware struct {
    apiKeyService *services.APIKeyService
}

func NewAPIKeyMiddleware(apiKeyService *services.APIKeyService) *APIKeyMiddleware {
    return &APIKeyMiddleware{apiKeyService: apiKeyService}
}

// ValidateAPIKey validates API key from Authorization header
func (m *APIKeyMiddleware) ValidateAPIKey() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
            c.Abort()
            return
        }

        // Extract API key (format: "Bearer <api_key>")
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
            c.Abort()
            return
        }

        apiKey := parts[1]

        // Validate API key
        key, err := m.apiKeyService.ValidateAPIKey(apiKey)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            c.Abort()
            return
        }

        // Set tenant context from API key
        c.Set("tenant_id", key.TenantID)
        c.Set("api_key_id", key.ID)
        c.Set("api_key_scopes", key.Scopes)

        c.Next()
    }
}

// RequireScope ensures API key has required scope
func (m *APIKeyMiddleware) RequireScope(requiredScope string) gin.HandlerFunc {
    return func(c *gin.Context) {
        scopes, exists := c.Get("api_key_scopes")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{"error": "No scopes available"})
            c.Abort()
            return
        }

        scopeList := scopes.([]string)
        hasScope := false
        for _, scope := range scopeList {
            if scope == requiredScope || scope == "*" {
                hasScope = true
                break
            }
        }

        if !hasScope {
            c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient scope"})
            c.Abort()
            return
        }

        c.Next()
    }
}
```

---

## PHASE 2F: POLICY TEMPLATES & ENHANCEMENTS (Week 9-10)

### Task 2F.1: Policy Templates

**File**: `internal/models/policy_template.go`

```go
package models

type PolicyTemplate struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Description string                 `json:"description"`
    Category    string                 `json:"category"` // 'time-based', 'location-based', 'attribute-based'
    Template    map[string]interface{} `json:"template"` // JSON template with placeholders
    Parameters  []TemplateParameter    `json:"parameters"`
    IsSystem    bool                   `json:"is_system"`
}

type TemplateParameter struct {
    Name        string   `json:"name"`
    Type        string   `json:"type"`
    Description string   `json:"description"`
    Required    bool     `json:"required"`
    DefaultValue interface{} `json:"default_value,omitempty"`
}

// Example templates
var SystemPolicyTemplates = []PolicyTemplate{
    {
        Name:        "Business Hours Access",
        Description: "Allow access only during business hours",
        Category:    "time-based",
        Template: map[string]interface{}{
            "conditions": map[string]interface{}{
                "time_range": map[string]interface{}{
                    "start_hour": "{{start_hour}}",
                    "end_hour":   "{{end_hour}}",
                    "timezone":   "{{timezone}}",
                    "weekdays":   "{{weekdays}}",
                },
            },
            "effect": "allow",
        },
        Parameters: []TemplateParameter{
            {Name: "start_hour", Type: "number", Description: "Business start hour (0-23)", Required: true},
            {Name: "end_hour", Type: "number", Description: "Business end hour (0-23)", Required: true},
            {Name: "timezone", Type: "string", Description: "Timezone", Required: true, DefaultValue: "UTC"},
            {Name: "weekdays", Type: "array", Description: "Allowed weekdays", Required: true, DefaultValue: []int{1, 2, 3, 4, 5}},
        },
        IsSystem: true,
    },
    {
        Name:        "Department-Scoped Access",
        Description: "User can only access resources in their department",
        Category:    "attribute-based",
        Template: map[string]interface{}{
            "conditions": map[string]interface{}{
                "attribute_match": map[string]interface{}{
                    "user_attribute":     "department",
                    "resource_attribute": "department",
                    "operator":           "equals",
                },
            },
            "effect": "allow",
        },
        Parameters: []TemplateParameter{},
        IsSystem:   true,
    },
    {
        Name:        "Amount-Based Approval",
        Description: "Require additional approval for amounts above threshold",
        Category:    "attribute-based",
        Template: map[string]interface{}{
            "conditions": map[string]interface{}{
                "numeric_comparison": map[string]interface{}{
                    "attribute": "amount",
                    "operator":  "greater_than",
                    "value":     "{{threshold}}",
                },
                "requires_approval": true,
            },
            "effect": "deny",
        },
        Parameters: []TemplateParameter{
            {Name: "threshold", Type: "number", Description: "Amount threshold", Required: true},
        },
        IsSystem: true,
    },
}
```

### Task 2F.2: Delegation Models

**File**: `database-migrations/migrations/000016_create_delegations_table.up.sql`

```sql
CREATE TABLE delegations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    delegator_id UUID REFERENCES users(id) ON DELETE CASCADE,
    delegate_id UUID REFERENCES users(id) ON DELETE CASCADE,
    scope JSONB NOT NULL, -- Array of permissions being delegated
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_delegations_tenant ON delegations(tenant_id);
CREATE INDEX idx_delegations_delegator ON delegations(delegator_id);
CREATE INDEX idx_delegations_delegate ON delegations(delegate_id);
```

---

## PHASE 2G: MIGRATION & DEPLOYMENT (Week 11-12)

### Task 2G.1: Phase 1 to Phase 2 Migration Script

**File**: `scripts/migrate-phase1-to-phase2.sh`

```bash
#!/bin/bash

set -e

echo "Starting Phase 1 to Phase 2 migration..."

# Step 1: Backup existing database
echo "1. Creating database backup..."
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > backup_phase1_$(date +%Y%m%d_%H%M%S).sql

# Step 2: Create default tenant for existing data
echo "2. Creating default tenant..."
psql -h $DB_HOST -U $DB_USER -d $DB_NAME <<EOF
INSERT INTO tenants (id, name, subdomain, is_active)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Tenant', 'default', true)
ON CONFLICT DO NOTHING;
EOF

# Step 3: Migrate existing users to default tenant
echo "3. Migrating existing users..."
psql -h $DB_HOST -U $DB_USER -d $DB_NAME <<EOF
UPDATE users
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

UPDATE roles
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

UPDATE permissions
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;

UPDATE tasks
SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE tenant_id IS NULL;
EOF

# Step 4: Run new migrations
echo "4. Running Phase 2 migrations..."
migrate -path database-migrations/migrations -database "$DATABASE_URL" up

# Step 5: Seed Phase 2 data
echo "5. Seeding Phase 2 data..."
psql -h $DB_HOST -U $DB_USER -d $DB_NAME < scripts/seed-phase2.sql

echo "Migration completed successfully!"
```

### Task 2G.2: Enhanced Seed Data

**File**: `scripts/seed-phase2.sql`

```sql
-- Insert system policy templates
INSERT INTO policy_templates (name, description, category, template, is_system) VALUES
    ('Business Hours Access', 'Allow access only during business hours', 'time-based', 
     '{"conditions": {"time_range": {}}, "effect": "allow"}', true),
    ('Department-Scoped Access', 'User can only access resources in their department', 'attribute-based',
     '{"conditions": {"attribute_match": {"user_attribute": "department", "resource_attribute": "department"}}, "effect": "allow"}', true);

-- Create sample webhook (optional - for testing)
-- INSERT INTO webhooks (tenant_id, name, url, secret, events, is_active) VALUES
--     ('00000000-0000-0000-0000-000000000001', 'Test Webhook', 'https://webhook.site/your-unique-url', 
--      'webhook_secret_key', '["user.created", "role.assigned"]', true);

-- Update existing resource types to be system resources
UPDATE resource_types SET is_system = true WHERE name IN ('task', 'user', 'profile');
```

### Task 2G.3: Docker Compose for Phase 2

**File**: `docker-compose.phase2.yml`

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: ${DB_USER:-taskmanager}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-password123}
      POSTGRES_DB: ${DB_NAME:-taskmanager}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-taskmanager}"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - ENV=production
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=${DB_USER:-taskmanager}
      - DB_PASSWORD=${DB_PASSWORD:-password123}
      - DB_NAME=${DB_NAME:-taskmanager}
      - JWT_SECRET=${JWT_SECRET:-your-secret-key}
      - REDIS_URL=redis://redis:6379
      - OAUTH_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - OAUTH_GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - OAUTH_GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - OAUTH_GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - EMAIL_SMTP_HOST=${SMTP_HOST}
      - EMAIL_SMTP_PORT=${SMTP_PORT}
      - EMAIL_FROM=${EMAIL_FROM}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped

  webhook-worker:
    build:
      context: .
      dockerfile: Dockerfile
    command: ["./bin/webhook-worker"]
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=${DB_USER:-taskmanager}
      - DB_PASSWORD=${DB_PASSWORD:-password123}
      - DB_NAME=${DB_NAME:-taskmanager}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

---

## IMPLEMENTATION TIMELINE

### Phase 2A: Multi-Tenancy Foundation (Weeks 1-2)
- [ ] Create tenants table migration
- [ ] Add tenant_id to all existing tables
- [ ] Implement tenant repository and service
- [ ] Create tenant middleware for isolation
- [ ] Update all existing repositories for multi-tenancy
- [ ] Test tenant isolation thoroughly

### Phase 2B: Advanced Authentication (Weeks 3-5)
- [ ] Implement OAuth 2.0 providers (Google, GitHub)
- [ ] Add email verification system
- [ ] Implement password reset flows
- [ ] Add MFA/2FA support (TOTP)
- [ ] Implement magic link authentication
- [ ] Test all authentication flows

### Phase 2C: Dynamic Resource Registration (Week 6)
- [ ] Create enhanced resource_types schema
- [ ] Implement resource registration API
- [ ] Create resource management service
- [ ] Add resource registration handlers
- [ ] Test external apps registering resources

### Phase 2D: Client SDKs (Week 7)
- [ ] Build Go SDK with full feature support
- [ ] Build JavaScript/Node.js SDK
- [ ] Build Python SDK
- [ ] Create SDK documentation
- [ ] Publish SDKs to package registries

### Phase 2E: Webhooks & API Keys (Week 8)
- [ ] Implement webhook system with retries
- [ ] Add API key generation and validation
- [ ] Create webhook delivery tracking
- [ ] Implement API key middleware
- [ ] Test webhook notifications

### Phase 2F: Policy Templates & Enhancements (Weeks 9-10)
- [ ] Create system policy templates
- [ ] Implement delegation system
- [ ] Add policy versioning
- [ ] Create policy simulation endpoint
- [ ] Test complex policy scenarios

### Phase 2G: Migration & Deployment (Weeks 11-12)
- [ ] Create Phase 1 to Phase 2 migration script
- [ ] Test migration on staging environment
- [ ] Deploy Phase 2 to production
- [ ] Monitor system performance
- [ ] Update documentation

---

## KEY DIFFERENCES FROM PHASE 1

| Aspect | Phase 1 (Taskify) | Phase 2 (IAM Platform) |
|--------|-------------------|------------------------|
| **Authentication** | Basic email/password + JWT | OAuth, MFA, Email verification, Magic links |
| **Authorization** | RBAC/ABAC for tasks | Multi-tenant RBAC/ABAC for any resource |
| **Resources** | Hardcoded (tasks only) | Dynamic registration by external apps |
| **Users** | Single organization | Multi-tenant with isolation |
| **Integration** | Internal use only | REST API + SDKs (Go, JS, Python) |
| **Notifications** | None | Webhooks for events |
| **API Access** | JWT tokens only | JWT tokens + API keys |
| **Policies** | Basic ABAC | Policy templates + versioning |
| **Delegation** | None | Permission delegation support |
| **Use Case** | Task management | IAM service for any application |

---

## SUCCESS CRITERIA FOR PHASE 2

✅ **Multi-Tenancy**
- Multiple tenants can be created and managed
- Complete data isolation between tenants
- Tenant-scoped permissions and roles
- Tenant settings customization

✅ **Advanced Authentication**
- OAuth 2.0 login with Google and GitHub works
- Email verification system functional
- Password reset flows secure and working
- MFA/2FA can be enabled and validated
- Magic links for passwordless login

✅ **Dynamic Resources**
- External apps can register resource types
- Custom actions can be defined for resources
- Attribute definitions for resources
- Resource management APIs functional

✅ **Client SDKs**
- Go SDK published and documented
- JavaScript SDK published to npm
- Python SDK published to PyPI
- All SDKs support core authorization functions
- SDK examples and guides available

✅ **External Integration**
- Webhooks send notifications for key events
- Webhook delivery tracking and retries
- API keys can be generated and validated
- API key scopes properly enforced

✅ **Policy Enhancements**
- System policy templates available
- Custom policy templates can be created
- Delegation system functional
- Policy simulation endpoint works

✅ **Migration & Backward Compatibility**
- Phase 1 data successfully migrated
- Existing functionality still works
- Taskify app continues to function as demo
- No breaking changes for existing users

---

## POST-IMPLEMENTATION CHECKLIST

### Documentation
- [ ] Complete API documentation for all new endpoints
- [ ] SDK guides for Go, JavaScript, and Python
- [ ] Integration examples for common use cases
- [ ] Migration guide from Phase 1 to Phase 2
- [ ] Webhook event reference documentation
- [ ] Policy template catalog

### Testing
- [ ] Unit tests for all new services
- [ ] Integration tests for multi-tenancy
- [ ] E2E tests for OAuth flows
- [ ] Webhook delivery tests
- [ ] SDK integration tests
- [ ] Load testing for multi-tenant scenarios

### Security
- [ ] Security audit of OAuth implementation
- [ ] Penetration testing for multi-tenancy
- [ ] Review API key security
- [ ] Validate tenant isolation
- [ ] Test webhook signature validation

### Performance
- [ ] Optimize database queries for tenant filtering
- [ ] Add caching for permissions (Redis)
- [ ] Implement rate limiting per tenant
- [ ] Monitor webhook delivery performance
- [ ] Optimize policy evaluation

### Monitoring
- [ ] Set up metrics for tenant usage
- [ ] Monitor webhook delivery success rates
- [ ] Track API key usage
- [ ] Alert on failed authentications
- [ ] Monitor resource registration

---

## OPTIONAL ENHANCEMENTS (Phase 2+)

### Admin Dashboard (Web UI)
- Tenant management interface
- User management UI
- Policy visual editor
- Audit logs viewer
- Analytics and usage metrics

### Additional OAuth Providers
- Microsoft Azure AD
- Apple Sign In
- Facebook Login
- Custom SAML providers

### Advanced Features
- IP allowlisting/blocklisting per tenant
- Custom branding per tenant
- Usage-based billing integration
- Export compliance reports (GDPR, SOC2)
- Session management dashboard

### Developer Portal
- Interactive API documentation
- SDK code generators
- Webhook testing tools
- Policy simulator UI
- Integration marketplace

---

*End of Phase 2 Implementation Plan*

**Next Steps**: After completing Phase 2, your IAM Authorization Service will be a full-featured, production-ready platform that can serve as the authentication and authorization backbone for multiple applications, positioning it as a viable alternative to services like Auth0, Firebase Authentication, or AWS Cognito, with a strong focus on fine-grained authorization.



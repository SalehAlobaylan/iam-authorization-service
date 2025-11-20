# Phase 2: IAM Authorization Service - Generalization Plan

## Overview

Transform the Taskify application into a production-ready IAM Authorization-as-a-Service platform. This phase adds advanced authentication features, multi-tenant architecture, external integration capabilities, and transforms the authorization engine to be resource-agnostic and reusable by any application.

## Project Context

- **Phase**: Generalization (Phase 2 - Post-Taskify)
- **Foundation**: Built on Taskify's RBAC/ABAC authorization engine
- **Goal**: Create a Firebase/Auth0 alternative with superior authorization capabilities
- **Architecture**: Multi-tenant SaaS with external integration support

---

## Architecture Transformation

### Current State (Taskify)

```
Monolithic Application
├── Basic Authentication (email/password + JWT)
├── Advanced Authorization (RBAC/ABAC)
└── Task Management (tightly coupled)
```

### Target State (IAM Service)

```
IAM Platform Service
├── Enhanced Authentication Module
│   ├── Multiple Identity Providers (OAuth, SAML)
│   ├── Advanced Security (MFA, email verification)
│   └── Session Management
├── Generalized Authorization Module
│   ├── Multi-tenant RBAC/ABAC Engine
│   ├── Dynamic Resource Registration
│   └── Policy Templates
├── External Integration Layer
│   ├── REST API
│   ├── Client SDKs (Go, Node.js, Python)
│   └── Webhooks
├── Platform Features
│   ├── Admin Dashboard
│   ├── Tenant Management
│   ├── Usage Analytics
│   └── Audit Logging
└── Demo Applications
    └── Taskify (now a client application)
```

---

## Implementation Phases

## Phase 2.1: Multi-Tenancy Foundation (Week 1-2)

### 2.1.1 Multi-Tenant Database Architecture

**Migration: Add Tenant Support**

Create `database-migrations/migrations/100001_add_multi_tenancy.up.sql`:

```sql
-- Tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    subdomain VARCHAR(50) UNIQUE,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX idx_tenants_is_active ON tenants(is_active);

-- Add tenant_id to existing tables
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE roles ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE permissions ADD COLUMN tenant_id UUID NULL; -- NULL for system-wide permissions
ALTER TABLE tasks ADD COLUMN tenant_id UUID REFERENCES tenants(id);

-- Create indexes for tenant isolation
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_roles_tenant ON roles(tenant_id);
CREATE INDEX idx_tasks_tenant ON tasks(tenant_id);

-- Tenant administrators
CREATE TABLE tenant_admins (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);

-- API keys for tenant applications
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    scopes JSONB DEFAULT '[]',
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked BOOLEAN DEFAULT false
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
```

**Backward Compatibility:**

- Create default tenant for existing Taskify data
- Migrate existing users, roles, and tasks to default tenant
- Maintain existing functionality for single-tenant mode

### 2.1.2 Tenant Models and Repository

Create `internal/models/tenant.go`:

```go
type Tenant struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Subdomain string                 `json:"subdomain"`
    Settings  map[string]interface{} `json:"settings"`
    IsActive  bool                   `json:"is_active"`
    CreatedAt time.Time              `json:"created_at"`
    UpdatedAt time.Time              `json:"updated_at"`
}

type APIKey struct {
    ID          string    `json:"id"`
    TenantID    string    `json:"tenant_id"`
    Name        string    `json:"name"`
    Key         string    `json:"key"` // Only returned on creation
    KeyHash     string    `json:"-"`
    Scopes      []string  `json:"scopes"`
    LastUsedAt  *time.Time `json:"last_used_at"`
    ExpiresAt   *time.Time `json:"expires_at"`
    CreatedAt   time.Time `json:"created_at"`
    Revoked     bool      `json:"revoked"`
}

type CreateTenantRequest struct {
    Name      string                 `json:"name" binding:"required"`
    Subdomain string                 `json:"subdomain" binding:"required"`
    Settings  map[string]interface{} `json:"settings"`
}
```

Create `internal/repository/tenant_repository.go`:

- `CreateTenant(tenant *Tenant) error`
- `GetTenantByID(tenantID string) (*Tenant, error)`
- `GetTenantBySubdomain(subdomain string) (*Tenant, error)`
- `UpdateTenant(tenantID string, updates map[string]interface{}) error`
- `DeactivateTenant(tenantID string) error`
- `CreateAPIKey(apiKey *APIKey) error`
- `GetAPIKeyByHash(keyHash string) (*APIKey, error)`
- `RevokeAPIKey(keyID string) error`

### 2.1.3 Tenant Context Middleware

Create `internal/middleware/tenant.go`:

```go
// Extract tenant from subdomain or API key
func TenantMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        var tenantID string
        
        // Check for API key in Authorization header
        if apiKey := extractAPIKey(c); apiKey != "" {
            tenant, err := tenantService.GetTenantByAPIKey(apiKey)
            if err != nil {
                c.JSON(401, gin.H{"error": "Invalid API key"})
                c.Abort()
                return
            }
            tenantID = tenant.ID
        } else {
            // Extract from subdomain (e.g., acme.iam-service.com)
            subdomain := extractSubdomain(c.Request.Host)
            tenant, err := tenantService.GetTenantBySubdomain(subdomain)
            if err != nil {
                c.JSON(404, gin.H{"error": "Tenant not found"})
                c.Abort()
                return
            }
            tenantID = tenant.ID
        }
        
        // Store tenant_id in context
        c.Set("tenant_id", tenantID)
        c.Next()
    }
}
```

### 2.1.4 Update All Queries for Tenant Isolation

Update all repository methods to filter by tenant_id:

- `internal/repository/user_repository.go` - add tenant_id to all queries
- `internal/repository/role_repository.go` - add tenant_id to all queries
- `internal/repository/task_repository.go` - add tenant_id to all queries
- Ensure no cross-tenant data leakage

---

## Phase 2.2: Enhanced Authentication Module (Week 2-4)

### 2.2.1 OAuth 2.0 Provider Integration

**Dependencies:**

```bash
go get golang.org/x/oauth2
go get github.com/markbates/goth
go get github.com/markbates/goth/providers/google
go get github.com/markbates/goth/providers/github
```

Create `internal/services/oauth_service.go`:

```go
type OAuthProvider string

const (
    ProviderGoogle OAuthProvider = "google"
    ProviderGitHub OAuthProvider = "github"
)

type OAuthService struct {
    providers map[OAuthProvider]*oauth2.Config
    userRepo  *repository.UserRepository
}

// Initiate OAuth flow
func (s *OAuthService) GetAuthURL(provider OAuthProvider, tenantID string) (string, error)

// Handle OAuth callback
func (s *OAuthService) HandleCallback(provider OAuthProvider, code string, tenantID string) (*User, *TokenPair, error)

// Link OAuth account to existing user
func (s *OAuthService) LinkAccount(userID string, provider OAuthProvider, oauthUserID string) error
```

**Migration: OAuth Accounts**

```sql
CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_oauth_user ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_provider ON oauth_accounts(provider, provider_user_id);
```

**New Handlers:**

- `POST /v1/auth/oauth/:provider` - Initiate OAuth flow
- `GET /v1/auth/oauth/:provider/callback` - Handle OAuth callback
- `POST /v1/auth/oauth/link` - Link OAuth account to existing user

### 2.2.2 Email Verification

Create `internal/services/email_service.go`:

```go
type EmailService struct {
    smtpHost     string
    smtpPort     int
    smtpUsername string
    smtpPassword string
    fromAddress  string
}

func (s *EmailService) SendVerificationEmail(userID, email string) error
func (s *EmailService) SendPasswordResetEmail(userID, email string) error
func (s *EmailService) SendMFACode(userID, email string, code string) error
```

**Migration: Email Verification**

```sql
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN email_verification_token VARCHAR(255);
ALTER TABLE users ADD COLUMN email_verification_expires_at TIMESTAMP;

CREATE INDEX idx_users_verification_token ON users(email_verification_token);

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_reset_token_hash ON password_reset_tokens(token_hash);
```

**New Endpoints:**

- `POST /v1/auth/verify-email` - Verify email with token
- `POST /v1/auth/resend-verification` - Resend verification email
- `POST /v1/auth/forgot-password` - Request password reset
- `POST /v1/auth/reset-password` - Reset password with token

### 2.2.3 Multi-Factor Authentication (MFA)

**Dependencies:**

```bash
go get github.com/pquerna/otp
go get github.com/skip2/go-qrcode
```

Create `internal/services/mfa_service.go`:

```go
type MFAService struct {
    userRepo *repository.UserRepository
}

// Generate TOTP secret and QR code
func (s *MFAService) GenerateTOTPSecret(userID string) (secret string, qrCode []byte, error)

// Enable MFA for user
func (s *MFAService) EnableMFA(userID, code string) error

// Disable MFA for user
func (s *MFAService) DisableMFA(userID, code string) error

// Verify TOTP code
func (s *MFAService) VerifyTOTP(userID, code string) (bool, error)

// Generate backup codes
func (s *MFAService) GenerateBackupCodes(userID string) ([]string, error)
```

**Migration: MFA Support**

```sql
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255);

CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_mfa_backup_user ON mfa_backup_codes(user_id);
```

**New Endpoints:**

- `POST /v1/auth/mfa/setup` - Initiate MFA setup
- `POST /v1/auth/mfa/enable` - Enable MFA with verification
- `POST /v1/auth/mfa/disable` - Disable MFA
- `POST /v1/auth/mfa/verify` - Verify MFA code during login
- `GET /v1/auth/mfa/backup-codes` - Generate backup codes

### 2.2.4 Session Management

Create `internal/services/session_service.go`:

```go
type Session struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id"`
    DeviceInfo string   `json:"device_info"`
    IPAddress string    `json:"ip_address"`
    UserAgent string    `json:"user_agent"`
    LastActivity time.Time `json:"last_activity"`
    CreatedAt time.Time `json:"created_at"`
}

func (s *SessionService) CreateSession(userID, ipAddress, userAgent string) (*Session, error)
func (s *SessionService) GetUserSessions(userID string) ([]*Session, error)
func (s *SessionService) RevokeSession(sessionID, userID string) error
func (s *SessionService) RevokeAllSessions(userID string) error
```

**Migration: Sessions**

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_info VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity);
```

**New Endpoints:**

- `GET /v1/auth/sessions` - List user's active sessions
- `DELETE /v1/auth/sessions/:sessionId` - Revoke specific session
- `DELETE /v1/auth/sessions` - Revoke all sessions (except current)

---

## Phase 2.3: Generalized Authorization Engine (Week 4-6)

### 2.3.1 Abstract Resource Model

Transform authorization to work with any resource type, not just tasks.

Update `internal/models/authorization.go`:

```go
// Generic access request
type AccessRequest struct {
    SubjectID    string                 `json:"subject_id"`
    TenantID     string                 `json:"tenant_id"`
    ResourceType string                 `json:"resource_type"`
    ResourceID   string                 `json:"resource_id"`
    Action       string                 `json:"action"`
    Context      map[string]interface{} `json:"context"`
}

type AccessResponse struct {
    Allowed bool     `json:"allowed"`
    Reason  string   `json:"reason"`
    Policies []string `json:"policies_evaluated"`
}

// Resource type definition
type ResourceTypeDefinition struct {
    ID          string              `json:"id"`
    TenantID    string              `json:"tenant_id"`
    Name        string              `json:"name"`
    Description string              `json:"description"`
    Actions     []string            `json:"actions"`
    Attributes  []ResourceAttribute `json:"attributes"`
}

type ResourceAttribute struct {
    Name        string   `json:"name"`
    Type        string   `json:"type"` // string, number, boolean, array
    Description string   `json:"description"`
    Required    bool     `json:"required"`
    Values      []string `json:"values,omitempty"` // For enum types
}
```

### 2.3.2 Dynamic Resource Registration

Allow external applications to register their resources dynamically.

Create `internal/services/resource_service.go`:

```go
type ResourceService struct {
    repo *repository.ResourceRepository
}

func (s *ResourceService) RegisterResourceType(tenantID string, definition *ResourceTypeDefinition) error
func (s *ResourceService) GetResourceTypes(tenantID string) ([]*ResourceTypeDefinition, error)
func (s *ResourceService) UpdateResourceType(tenantID, resourceTypeID string, updates *ResourceTypeDefinition) error
func (s *ResourceService) DeleteResourceType(tenantID, resourceTypeID string) error
```

**Migration: Resource Type Registry**

```sql
-- Already have resource_types, make it tenant-aware
ALTER TABLE resource_types ADD COLUMN tenant_id UUID REFERENCES tenants(id);
ALTER TABLE resource_types ADD COLUMN is_system BOOLEAN DEFAULT false; -- System-wide resources

-- Resource attributes definition
CREATE TABLE resource_type_attributes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type_id UUID NOT NULL REFERENCES resource_types(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    description TEXT,
    required BOOLEAN DEFAULT false,
    allowed_values JSONB, -- For enum types
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_resource_attrs_type ON resource_type_attributes(resource_type_id);

-- Actions available for each resource type
CREATE TABLE resource_type_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type_id UUID NOT NULL REFERENCES resource_types(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    UNIQUE(resource_type_id, action)
);
```

**New Endpoints:**

- `POST /v1/authz/resources` - Register new resource type
- `GET /v1/authz/resources` - List registered resource types
- `GET /v1/authz/resources/:resourceTypeId` - Get resource type details
- `PUT /v1/authz/resources/:resourceTypeId` - Update resource type
- `DELETE /v1/authz/resources/:resourceTypeId` - Delete resource type

### 2.3.3 Enhanced Authorization Service

Update `internal/services/authz_service.go`:

```go
type AuthzService struct {
    roleRepo       *repository.RoleRepository
    permissionRepo *repository.PermissionRepository
    policyRepo     *repository.PolicyRepository
    resourceRepo   *repository.ResourceRepository
    cache          CacheService
}

// Generic authorization check
func (s *AuthzService) Authorize(req *AccessRequest) (*AccessResponse, error) {
    // 1. Check cache
    if cached := s.cache.GetAuthorization(req); cached != nil {
        return cached, nil
    }
    
    // 2. Evaluate RBAC permissions
    rbacAllowed, _ := s.evaluateRBAC(req)
    
    // 3. Evaluate ABAC policies
    abacAllowed, policies := s.evaluateABAC(req)
    
    // 4. Combine results (RBAC OR ABAC)
    allowed := rbacAllowed || abacAllowed
    
    // 5. Cache result
    response := &AccessResponse{
        Allowed: allowed,
        Reason: s.generateReason(rbacAllowed, abacAllowed),
        Policies: policies,
    }
    s.cache.SetAuthorization(req, response, 5*time.Minute)
    
    // 6. Audit log
    s.auditLog(req, response)
    
    return response, nil
}

// Batch authorization check
func (s *AuthzService) AuthorizeBatch(requests []*AccessRequest) ([]*AccessResponse, error)

// Get user's effective permissions
func (s *AuthzService) GetUserPermissions(tenantID, userID string) ([]Permission, error)

// Policy simulation (test access without enforcement)
func (s *AuthzService) SimulateAccess(req *AccessRequest) (*AccessResponse, error)
```

### 2.3.4 Policy Templates

Create reusable policy patterns.

Create `internal/services/policy_template_service.go`:

```go
type PolicyTemplate struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Description string                 `json:"description"`
    Template    map[string]interface{} `json:"template"`
    Variables   []TemplateVariable     `json:"variables"`
    IsSystem    bool                   `json:"is_system"`
}

type TemplateVariable struct {
    Name        string `json:"name"`
    Type        string `json:"type"`
    Description string `json:"description"`
    Required    bool   `json:"required"`
}

func (s *PolicyTemplateService) CreateTemplate(template *PolicyTemplate) error
func (s *PolicyTemplateService) InstantiateTemplate(templateID string, variables map[string]interface{}) (*Policy, error)
func (s *PolicyTemplateService) ListTemplates() ([]*PolicyTemplate, error)
```

**Migration: Policy Templates**

```sql
CREATE TABLE policy_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    template JSONB NOT NULL,
    variables JSONB NOT NULL,
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_policy_templates_system ON policy_templates(is_system);
```

**Predefined Templates:**

- Department-scoped access
- Time-based access (business hours only)
- Resource ownership
- Approval workflows
- IP-based restrictions

**New Endpoints:**

- `POST /v1/authz/policy-templates` - Create policy template
- `GET /v1/authz/policy-templates` - List policy templates
- `POST /v1/authz/policy-templates/:templateId/instantiate` - Create policy from template

---

## Phase 2.4: Caching Layer with Redis (Week 6-7)

### 2.4.1 Redis Integration

**Dependencies:**

```bash
go get github.com/go-redis/redis/v8
```

Create `internal/cache/redis_cache.go`:

```go
type RedisCache struct {
    client *redis.Client
}

func NewRedisCache(addr, password string, db int) (*RedisCache, error)

// Permission caching
func (c *RedisCache) GetAuthorization(req *AccessRequest) *AccessResponse
func (c *RedisCache) SetAuthorization(req *AccessRequest, response *AccessResponse, ttl time.Duration)
func (c *RedisCache) InvalidateUserPermissions(tenantID, userID string)
func (c *RedisCache) InvalidateTenantPermissions(tenantID string)

// Token blacklist (for revoked tokens)
func (c *RedisCache) BlacklistToken(token string, ttl time.Duration)
func (c *RedisCache) IsTokenBlacklisted(token string) bool

// Rate limiting
func (c *RedisCache) IncrementRateLimit(key string, limit int, window time.Duration) (int, error)
```

**Cache Invalidation Strategy:**

- Invalidate on policy updates
- Invalidate on role/permission changes
- TTL-based expiration (5-15 minutes)
- Event-driven invalidation

**Configuration:**

Add to `config/config.yaml`:

```yaml
redis:
  host: localhost
  port: "6379"
  password: ""
  db: 0
  cache_ttl: 300  # 5 minutes
```

### 2.4.2 Cache Middleware

Create `internal/middleware/cache.go`:

```go
func CacheMiddleware(cache *cache.RedisCache) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Check if request is cacheable
        if c.Request.Method != "GET" {
            c.Next()
            return
        }
        
        cacheKey := generateCacheKey(c.Request)
        
        // Try to get from cache
        if cached := cache.Get(cacheKey); cached != nil {
            c.JSON(200, cached)
            c.Abort()
            return
        }
        
        // Continue to handler
        c.Next()
        
        // Cache response if successful
        if c.Writer.Status() == 200 {
            cache.Set(cacheKey, c.Writer, 5*time.Minute)
        }
    }
}
```

---

## Phase 2.5: External Integration Layer (Week 7-9)

### 2.5.1 REST API for External Applications

Create dedicated authorization API endpoints:

**Authorization Evaluation:**

- `POST /v1/authz/evaluate` - Single authorization check
- `POST /v1/authz/evaluate/batch` - Batch authorization checks
- `GET /v1/authz/permissions/user/:userId` - Get user permissions
- `GET /v1/authz/permissions/role/:roleId` - Get role permissions

**Resource Management:**

- `POST /v1/authz/resources` - Register resource type
- `GET /v1/authz/resources` - List resource types
- `PUT /v1/authz/resources/:resourceTypeId` - Update resource type

**Policy Management:**

- `POST /v1/authz/policies` - Create policy
- `GET /v1/authz/policies` - List policies
- `PUT /v1/authz/policies/:policyId` - Update policy
- `DELETE /v1/authz/policies/:policyId` - Delete policy
- `POST /v1/authz/policies/simulate` - Simulate policy

**Role Management:**

- `POST /v1/authz/roles` - Create role
- `GET /v1/authz/roles` - List roles
- `POST /v1/authz/roles/:roleId/permissions` - Assign permissions
- `POST /v1/authz/users/:userId/roles` - Assign role to user

### 2.5.2 Client SDK - Go

Create `pkg/authz/client.go`:

```go
package authz

type Client struct {
    baseURL   string
    apiKey    string
    tenantID  string
    httpClient *http.Client
}

func NewClient(config ClientConfig) *Client

// Authorization methods
func (c *Client) Authorize(ctx context.Context, req AccessRequest) (bool, error)
func (c *Client) AuthorizeBatch(ctx context.Context, requests []AccessRequest) ([]AccessResponse, error)
func (c *Client) Can(ctx context.Context, userID, permission string) (bool, error)
func (c *Client) CanWithContext(ctx context.Context, userID, permission string, context map[string]interface{}) (bool, error)

// Resource management
func (c *Client) RegisterResource(ctx context.Context, resource ResourceTypeDefinition) error
func (c *Client) ListResources(ctx context.Context) ([]ResourceTypeDefinition, error)

// Role management
func (c *Client) CreateRole(ctx context.Context, role Role) error
func (c *Client) AssignRoleToUser(ctx context.Context, userID, roleID string) error
func (c *Client) GetUserRoles(ctx context.Context, userID string) ([]Role, error)

// Policy management
func (c *Client) CreatePolicy(ctx context.Context, policy Policy) error
func (c *Client) SimulatePolicy(ctx context.Context, req AccessRequest) (*AccessResponse, error)
```

### 2.5.3 Client SDK - Node.js

Create `sdk/nodejs/src/index.ts`:

```typescript
export class AuthzClient {
  private baseUrl: string;
  private apiKey: string;
  private tenantId: string;

  constructor(config: ClientConfig) {
    this.baseUrl = config.baseUrl;
    this.apiKey = config.apiKey;
    this.tenantId = config.tenantId;
  }

  async authorize(req: AccessRequest): Promise<boolean> {
    const response = await this.request('POST', '/v1/authz/evaluate', req);
    return response.allowed;
  }

  async authorizeBatch(requests: AccessRequest[]): Promise<AccessResponse[]> {
    return this.request('POST', '/v1/authz/evaluate/batch', { requests });
  }

  async can(userId: string, permission: string, resourceId?: string): Promise<boolean> {
    const [resource, action] = permission.split(':');
    return this.authorize({
      subjectId: userId,
      resourceType: resource,
      resourceId,
      action,
    });
  }

  async getUserPermissions(userId: string): Promise<Permission[]> {
    return this.request('GET', `/v1/authz/permissions/user/${userId}`);
  }
}
```

### 2.5.4 Client SDK - Python

Create `sdk/python/authz_client/__init__.py`:

```python
from typing import List, Dict, Optional
import requests

class AuthzClient:
    def __init__(self, base_url: str, api_key: str, tenant_id: str):
        self.base_url = base_url
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'X-Tenant-ID': tenant_id,
        })
    
    def authorize(self, req: Dict) -> bool:
        response = self.session.post(
            f'{self.base_url}/v1/authz/evaluate',
            json=req
        )
        response.raise_for_status()
        return response.json()['allowed']
    
    def can(self, user_id: str, permission: str, resource_id: Optional[str] = None) -> bool:
        resource, action = permission.split(':')
        return self.authorize({
            'subject_id': user_id,
            'resource_type': resource,
            'resource_id': resource_id,
            'action': action,
        })
    
    def get_user_permissions(self, user_id: str) -> List[Dict]:
        response = self.session.get(
            f'{self.base_url}/v1/authz/permissions/user/{user_id}'
        )
        response.raise_for_status()
        return response.json()
```

### 2.5.5 Webhook System

Allow applications to receive real-time notifications.

Create `internal/services/webhook_service.go`:

```go
type WebhookEvent string

const (
    EventUserCreated     WebhookEvent = "user.created"
    EventUserUpdated     WebhookEvent = "user.updated"
    EventUserDeleted     WebhookEvent = "user.deleted"
    EventRoleAssigned    WebhookEvent = "role.assigned"
    EventRoleRevoked     WebhookEvent = "role.revoked"
    EventPolicyCreated   WebhookEvent = "policy.created"
    EventPolicyUpdated   WebhookEvent = "policy.updated"
    EventAccessDenied    WebhookEvent = "access.denied"
)

type Webhook struct {
    ID        string         `json:"id"`
    TenantID  string         `json:"tenant_id"`
    URL       string         `json:"url"`
    Events    []WebhookEvent `json:"events"`
    Secret    string         `json:"secret"`
    IsActive  bool           `json:"is_active"`
    CreatedAt time.Time      `json:"created_at"`
}

func (s *WebhookService) CreateWebhook(webhook *Webhook) error
func (s *WebhookService) TriggerEvent(event WebhookEvent, payload interface{}) error
func (s *WebhookService) ListWebhooks(tenantID string) ([]*Webhook, error)
func (s *WebhookService) DeleteWebhook(webhookID string) error
```

**Migration: Webhooks**

```sql
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    events JSONB NOT NULL,
    secret VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    status_code INTEGER,
    response_body TEXT,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
```

---

## Phase 2.6: Admin Dashboard (Week 9-11)

### 2.6.1 Dashboard Backend API

Create admin-focused endpoints:

**Tenant Management:**

- `GET /v1/admin/tenants` - List all tenants (super admin)
- `GET /v1/admin/tenants/:tenantId/stats` - Tenant statistics
- `GET /v1/admin/tenants/:tenantId/users` - List tenant users
- `GET /v1/admin/tenants/:tenantId/usage` - Usage analytics

**User Management:**

- `GET /v1/admin/users` - List users with filters
- `GET /v1/admin/users/:userId/activity` - User activity log
- `GET /v1/admin/users/:userId/permissions` - User permission tree
- `PUT /v1/admin/users/:userId/status` - Activate/deactivate user

**Authorization Analytics:**

- `GET /v1/admin/analytics/access-patterns` - Access pattern analysis
- `GET /v1/admin/analytics/denied-requests` - Denied access attempts
- `GET /v1/admin/analytics/top-resources` - Most accessed resources
- `GET /v1/admin/analytics/policy-coverage` - Policy coverage report

**Audit Logs:**

- `GET /v1/admin/audit-logs` - Query audit logs with filters
- `GET /v1/admin/audit-logs/export` - Export audit logs (CSV/JSON)

### 2.6.2 Dashboard Frontend (Optional)

Technology: React + TypeScript + Tailwind CSS

**Key Features:**

- Tenant overview dashboard
- User management interface
- Role and permission builder (drag-and-drop)
- Policy editor with syntax highlighting
- Real-time access logs
- Analytics and reporting
- API key management
- Webhook configuration

**Dashboard Sections:**

1. Overview - Key metrics and charts
2. Users - User list, roles, activity
3. Roles - Role management, permission assignment
4. Policies - Policy editor, simulation tool
5. Resources - Resource type registry
6. Audit - Comprehensive audit log viewer
7. Settings - Tenant settings, API keys, webhooks

---

## Phase 2.7: Audit and Compliance (Week 11-12)

### 2.7.1 Comprehensive Audit Logging

**Migration: Enhanced Audit System**

```sql
CREATE TABLE authorization_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    subject_id UUID,
    subject_type VARCHAR(50), -- user, api_key, service_account
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    action VARCHAR(50) NOT NULL,
    decision VARCHAR(10) NOT NULL, -- allow, deny
    reason TEXT,
    policies_evaluated JSONB,
    context JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id UUID,
    request_id VARCHAR(100),
    duration_ms INTEGER,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON authorization_audit_log(tenant_id);
CREATE INDEX idx_audit_subject ON authorization_audit_log(subject_id);
CREATE INDEX idx_audit_resource ON authorization_audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_timestamp ON authorization_audit_log(timestamp);
CREATE INDEX idx_audit_decision ON authorization_audit_log(decision);

-- Authentication audit log
CREATE TABLE authentication_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL, -- login, logout, mfa_verified, password_reset
    status VARCHAR(50) NOT NULL, -- success, failure
    method VARCHAR(50), -- email, oauth_google, oauth_github
    ip_address VARCHAR(45),
    user_agent TEXT,
    error_message TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_tenant ON authentication_audit_log(tenant_id);
CREATE INDEX idx_auth_audit_user ON authentication_audit_log(user_id);
CREATE INDEX idx_auth_audit_timestamp ON authentication_audit_log(timestamp);
CREATE INDEX idx_auth_audit_status ON authentication_audit_log(status);
```

### 2.7.2 Audit Service

Create `internal/services/audit_service.go`:

```go
type AuditService struct {
    db *sql.DB
}

// Authorization audit
func (s *AuditService) LogAuthorizationDecision(log *AuthorizationAuditLog) error

// Authentication audit
func (s *AuditService) LogAuthenticationEvent(log *AuthenticationAuditLog) error

// Query audit logs
func (s *AuditService) QueryAuthorizationLogs(filters AuditFilters) ([]*AuthorizationAuditLog, error)
func (s *AuditService) QueryAuthenticationLogs(filters AuditFilters) ([]*AuthenticationAuditLog, error)

// Export audit logs
func (s *AuditService) ExportLogs(filters AuditFilters, format string) ([]byte, error)

// Compliance reports
func (s *AuditService) GenerateComplianceReport(tenantID string, reportType string, dateRange DateRange) (*ComplianceReport, error)
```

### 2.7.3 Compliance Reports

Predefined compliance reports:

- **GDPR Report**: Data access logs, consent tracking
- **HIPAA Report**: PHI access logs, authentication events
- **SOC2 Report**: Access control effectiveness, audit trail
- **PCI-DSS Report**: Payment data access logs

---

## Phase 2.8: Convert Taskify to Client Application (Week 12)

### 2.8.1 Extract Taskify as Separate Service

Restructure project:

```
iam-authorization-service/
├── cmd/
│   ├── iam-service/      # Main IAM service
│   │   └── main.go
│   └── taskify-demo/     # Taskify as demo app
│       └── main.go
├── internal/
│   ├── iam/              # IAM core services
│   └── taskify/          # Taskify-specific code
└── pkg/
    └── authz/            # Client SDK
```

### 2.8.2 Update Taskify to Use SDK

Transform Taskify to use the IAM service via SDK:

```go
// Old: Direct service call
allowed, err := h.authzService.CheckPermission(userID, "task", "delete", taskID)

// New: SDK client call
authzClient := authz.NewClient(authz.Config{
    BaseURL: os.Getenv("IAM_SERVICE_URL"),
    APIKey:  os.Getenv("IAM_API_KEY"),
    TenantID: os.Getenv("TENANT_ID"),
})

allowed, err := authzClient.Can(ctx, userID, "task:delete", taskID)
```

### 2.8.3 Taskify Registration with IAM Service

On Taskify startup:

```go
func registerTaskifyResources(client *authz.Client) error {
    // Register 'task' resource type
    return client.RegisterResource(context.Background(), authz.ResourceTypeDefinition{
        Name: "task",
        Description: "Task management resources",
        Actions: []string{"create", "read", "update", "delete"},
        Attributes: []authz.ResourceAttribute{
            {Name: "status", Type: "string"},
            {Name: "priority", Type: "string"},
            {Name: "owner_id", Type: "string"},
        },
    })
}
```

---

## Phase 2.9: Performance Optimization (Week 13)

### 2.9.1 Database Optimization

- Add missing indexes
- Implement connection pooling
- Query optimization for authorization checks
- Implement read replicas for analytics

### 2.9.2 API Rate Limiting

Create `internal/middleware/rate_limit.go`:

```go
func RateLimitMiddleware(cache *cache.RedisCache) gin.HandlerFunc {
    return func(c *gin.Context) {
        key := getRateLimitKey(c)
        count, err := cache.IncrementRateLimit(key, 100, time.Minute)
        
        if count > 100 {
            c.JSON(429, gin.H{"error": "Rate limit exceeded"})
            c.Abort()
            return
        }
        
        c.Header("X-RateLimit-Limit", "100")
        c.Header("X-RateLimit-Remaining", strconv.Itoa(100-count))
        c.Next()
    }
}
```

### 2.9.3 Monitoring and Observability

**Dependencies:**

```bash
go get github.com/prometheus/client_golang
go get go.opentelemetry.io/otel
```

Implement:

- Prometheus metrics (request count, latency, errors)
- OpenTelemetry tracing
- Health check endpoints
- Performance profiling endpoints

---

## Phase 2.10: Documentation and Developer Experience (Week 14)

### 2.10.1 API Documentation

- Complete OpenAPI 3.0 specification
- Interactive API explorer (Swagger UI)
- Code examples in multiple languages
- Authentication guide
- Authorization patterns guide

### 2.10.2 SDK Documentation

For each SDK:

- Installation guide
- Quick start tutorial
- API reference
- Code examples
- Best practices

### 2.10.3 Integration Guides

Create guides for:

- Integrating with Node.js applications
- Integrating with Python applications
- Integrating with Go applications
- API Gateway integration
- Microservices architecture patterns

### 2.10.4 Deployment Guide

- Docker deployment
- Kubernetes deployment (Helm charts)
- AWS/GCP/Azure deployment guides
- Configuration management
- Scaling strategies
- Backup and recovery

---

## Implementation Checklist

### Core Generalization (Must Have)

- [ ] Multi-tenant database architecture
- [ ] Tenant isolation and API keys
- [ ] OAuth 2.0 integration (Google, GitHub)
- [ ] Email verification system
- [ ] MFA/2FA support
- [ ] Session management
- [ ] Password reset flows
- [ ] Generic authorization engine (resource-agnostic)
- [ ] Dynamic resource registration
- [ ] Policy templates
- [ ] Redis caching layer
- [ ] Authorization API for external apps
- [ ] Go client SDK
- [ ] Comprehensive audit logging
- [ ] Convert Taskify to client application

### Enhanced Features (Important)

- [ ] Node.js client SDK
- [ ] Python client SDK
- [ ] Webhook system
- [ ] Admin dashboard backend API
- [ ] Analytics and reporting
- [ ] Rate limiting
- [ ] Prometheus metrics
- [ ] Compliance reports

### Optional Features (Nice to Have)

- [ ] Admin dashboard frontend
- [ ] SAML integration
- [ ] Magic link authentication
- [ ] Device management
- [ ] Advanced policy editor UI
- [ ] Policy visualization
- [ ] GitOps for policies
- [ ] Kubernetes Helm charts

---

## Development Timeline

### Month 1: Foundation

- **Week 1-2**: Multi-tenancy architecture
- **Week 3-4**: Enhanced authentication (OAuth, email verification)

### Month 2: Authentication & Authorization

- **Week 5-6**: MFA, session management, generalized authorization engine
- **Week 7-8**: Resource registration, policy templates, caching

### Month 3: External Integration

- **Week 9-10**: Client SDKs, webhooks, external API
- **Week 11-12**: Admin dashboard, audit logging

### Month 4: Polish & Launch

- **Week 13**: Performance optimization, monitoring
- **Week 14**: Documentation, deployment guides, demo applications

---

## Success Criteria

### Functional Requirements

- ✅ Multiple tenants can use the service independently
- ✅ Applications can register custom resource types
- ✅ External apps can integrate via REST API
- ✅ Client SDKs work correctly in Go, Node.js, Python
- ✅ OAuth login works for Google and GitHub
- ✅ MFA can be enabled and used
- ✅ Email verification and password reset work
- ✅ Caching improves authorization performance
- ✅ Audit logs capture all authorization decisions
- ✅ Taskify works as a client application

### Performance Requirements

- ✅ Authorization checks < 50ms (with cache)
- ✅ Authorization checks < 200ms (without cache)
- ✅ Support 1000+ requests/second
- ✅ 99.9% uptime

### Security Requirements

- ✅ Tenant data completely isolated
- ✅ No cross-tenant data leakage
- ✅ All authentication methods secure
- ✅ API keys properly hashed
- ✅ Comprehensive security audit passed

### Developer Experience

- ✅ Clear API documentation
- ✅ Easy SDK integration (< 10 lines of code)
- ✅ Comprehensive examples
- ✅ Good error messages
- ✅ Fast response times

---

## Migration Path

### For Existing Taskify Users

1. Create default tenant for existing data
2. Migrate users, roles, tasks to default tenant
3. Generate API key for Taskify application
4. Update Taskify to use IAM service via SDK
5. Maintain backward compatibility

### Data Migration Script

```sql
-- Create default tenant
INSERT INTO tenants (name, subdomain, settings) 
VALUES ('Default', 'default', '{}') 
RETURNING id;

-- Update existing data with tenant_id
UPDATE users SET tenant_id = 'default-tenant-id';
UPDATE roles SET tenant_id = 'default-tenant-id';
UPDATE tasks SET tenant_id = 'default-tenant-id';
```

---

## Post-Launch Enhancements

### Phase 3 Features (Future)

- [ ] Relationship-based access control (ReBAC)
- [ ] Policy versioning and rollback
- [ ] A/B testing for policies
- [ ] Machine learning for anomaly detection
- [ ] Advanced analytics dashboard
- [ ] Marketplace for policy templates
- [ ] Enterprise SSO (SAML, LDAP)
- [ ] Billing and usage tracking
- [ ] Self-service tenant onboarding
- [ ] Mobile SDK (iOS, Android)

---

## Technical Decisions

### Why Multi-Tenancy?

- Scale to support multiple organizations
- Data isolation and security
- Different configurations per tenant
- Foundation for SaaS business model

### Why OAuth Over Custom Implementation?

- Industry standard
- Better security (no password handling)
- User convenience (existing accounts)
- Reduced liability

### Why Redis for Caching?

- Fast in-memory storage
- Built-in TTL support
- Pub/sub for cache invalidation
- Production-proven

### Why SDKs in Multiple Languages?

- Broader adoption
- Better developer experience
- Hide API complexity
- Type safety and autocomplete

### Why Separate Taskify?

- Demonstrates platform capabilities
- Clean separation of concerns
- Easier to maintain
- Shows real-world usage

---

## Differentiation from Competitors

### vs Auth0

- ✅ Superior authorization (RBAC + ABAC)
- ✅ Custom resource types
- ✅ Policy templates
- ✅ Better pricing for authorization-heavy apps

### vs Firebase Auth

- ✅ Advanced authorization built-in
- ✅ Multi-tenant from the start
- ✅ Self-hosted option
- ✅ No vendor lock-in

### vs AWS IAM

- ✅ Simpler to use
- ✅ Better developer experience
- ✅ Works anywhere (not AWS-specific)
- ✅ Visual policy editor

### vs Keycloak

- ✅ Lighter weight
- ✅ Better authorization engine
- ✅ Modern API design
- ✅ Better documentation

---

This plan transforms Taskify into a production-ready IAM Authorization-as-a-Service platform that can compete with commercial offerings while maintaining the strong authorization foundation built in Phase 1.
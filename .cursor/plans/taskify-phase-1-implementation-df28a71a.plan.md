<!-- df28a71a-7318-4735-b3f9-4544b6a22332 fda950c3-7603-424c-bc9f-56b470f97ea0 -->
# Taskify Phase 1 Implementation Plan

## Project Context
Building a secure task management API for Railtronics with advanced authorization (RBAC + ABAC). The project follows the Udacity cd14130-starter architecture with Gin framework and PostgreSQL.

## Implementation Phases

### Phase 1: Project Setup and Configuration (Week 1)

**1.1 Initialize Go Dependencies**
- Update `go.mod` with required dependencies:
  - `github.com/gin-gonic/gin` (web framework)
  - `github.com/lib/pq` (PostgreSQL driver)
  - `github.com/golang-jwt/jwt/v5` (JWT tokens)
  - `golang.org/x/crypto/bcrypt` (password hashing)
  - `github.com/google/uuid` (UUID generation)
  - `gopkg.in/yaml.v3` (config parsing)
- Run `go mod tidy` and `go mod download`

**1.2 Configure Application Settings**
- Populate `config/config.yaml` with:
  - Server configuration (port, host)
  - Database connection details
  - JWT secret and token TTLs (1 hour for both access and refresh tokens)
  - Environment settings
- Create `config/config.go` to load and parse configuration
- Add `.env.example` file for environment variables

**1.3 Database Connection Setup**
- Implement `internal/database/postgres.go`:
  - Connection pool management
  - Health check function
  - Connection string builder from config
  - Proper error handling and logging

**1.4 Main Server Initialization**
- Create `cmd/api/main.go`:
  - Load configuration
  - Initialize database connection
  - Set up Gin router with middleware
  - Graceful shutdown handling
- Create `internal/api/server.go` for server setup
- Create `internal/api/router.go` for route definitions

**Deliverables:** Project builds successfully, connects to PostgreSQL, health endpoint responds

---

### Phase 2: User Registration (Week 1-2)

**2.1 Database Schema - Users Table**
- Create migration `database-migrations/migrations/000001_create_users_table.up.sql`:
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
- Create corresponding `.down.sql` for rollback
- Run migration using `golang-migrate` CLI

**2.2 User Model**
- Create `internal/models/user.go`:
  - User struct with JSON tags
  - RegisterRequest struct (email, password)
  - RegisterResponse struct (user data, no password)
  - Helper methods for data sanitization

**2.3 User Repository**
- Create `internal/repository/user_repository.go`:
  - `CreateUser(email, passwordHash string) (*User, error)`
  - `GetUserByEmail(email string) (*User, error)`
  - `GetUserByID(id string) (*User, error)`
  - Use parameterized queries to prevent SQL injection

**2.4 Authentication Service - Registration**
- Create `internal/services/auth_service.go`:
  - `Register(email, password string) (*User, error)`
  - Validate email format and password strength
  - Hash password using bcrypt (cost factor 12)
  - Call repository to create user
  - Assign default "user" role (to be implemented in RBAC phase)

**2.5 Registration Handler**
- Create `internal/handlers/auth_handler.go`:
  - `Register(c *gin.Context)` handler
  - Bind and validate JSON request
  - Call auth service
  - Return 201 Created with user data (exclude password)
  - Handle errors (duplicate email, validation failures)

**2.6 Register Route**
- Add `POST /v1/auth/register` route in `internal/api/router.go`
- No authentication required for this endpoint

**Deliverables:** Users can register successfully, passwords are hashed, duplicate emails rejected

---

### Phase 3: User Login and JWT Tokens (Week 2)

**3.1 Database Schema - Tokens Table**
- Create migration `000002_create_tokens_table.up.sql`:
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
- Create `.down.sql` migration

**3.2 Token Models**
- Create `internal/models/token.go`:
  - TokenPair struct (access_token, refresh_token, expires_in)
  - AccessTokenClaims struct extending jwt.RegisteredClaims
  - Include: user_id, email, roles, permissions, expiry
  - RefreshToken database model

**3.3 JWT Utilities**
- Create `internal/utils/jwt.go`:
  - `GenerateAccessToken(userID, email string, roles []string, permissions []Permission) (string, error)`
  - `GenerateRefreshToken() (string, error)` - random secure token
  - `ValidateAccessToken(tokenString string) (*AccessTokenClaims, error)`
  - Use JWT secret from config
  - Set expiry to 1 hour for both tokens

**3.4 Token Repository**
- Create `internal/repository/token_repository.go`:
  - `CreateRefreshToken(userID, token string, expiresAt time.Time) error`
  - `GetRefreshToken(token string) (*RefreshToken, error)`
  - `RevokeRefreshToken(token string) error`
  - `DeleteExpiredTokens() error`

**3.5 Authentication Service - Login**
- Update `internal/services/auth_service.go`:
  - `Login(email, password string) (*TokenPair, error)`
  - Retrieve user by email
  - Compare password hash using bcrypt
  - Get user roles and permissions (prepare for RBAC)
  - Generate JWT access token with claims
  - Generate and store refresh token
  - Return token pair

**3.6 Login Handler**
- Update `internal/handlers/auth_handler.go`:
  - `Login(c *gin.Context)` handler
  - Bind LoginRequest (email, password)
  - Call auth service
  - Return 200 OK with access_token, refresh_token, expires_in
  - Handle invalid credentials (401 Unauthorized)

**3.7 Login Route**
- Add `POST /v1/auth/login` route
- No authentication required

**Deliverables:** Users can login and receive JWT tokens, tokens contain proper claims

---

### Phase 4: Refresh Token Endpoint (Week 2)

**4.1 Refresh Token Service**
- Update `internal/services/auth_service.go`:
  - `RefreshAccessToken(refreshToken string) (*TokenPair, error)`
  - Validate refresh token exists and not expired
  - Verify token not revoked
  - Retrieve user and permissions
  - Generate new access token
  - Generate new refresh token and revoke old one
  - Return new token pair

**4.2 Refresh Token Handler**
- Update `internal/handlers/auth_handler.go`:
  - `RefreshToken(c *gin.Context)` handler
  - Extract refresh_token from request body
  - Call auth service
  - Return new token pair
  - Handle invalid/expired tokens (401)

**4.3 Refresh Route**
- Add `POST /v1/auth/refresh` route
- No authentication required (validates refresh token instead)

**Deliverables:** Users can get new access tokens using refresh tokens

---

### Phase 5: RBAC - Roles and Permissions (Week 3)

**5.1 Database Schema - RBAC Tables**
- Create migration `000003_create_rbac_tables.up.sql`:
  ```sql
  CREATE TABLE roles (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(50) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
  );
  
  CREATE TABLE user_roles (
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      assigned_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, role_id)
  );
  
  CREATE TABLE resource_types (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(50) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
  );
  
  CREATE TABLE permissions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      resource_type_id UUID NOT NULL REFERENCES resource_types(id),
      action VARCHAR(50) NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(resource_type_id, action)
  );
  
  CREATE TABLE role_permissions (
      role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
      assigned_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (role_id, permission_id)
  );
  ```
- Create `.down.sql` migration

**5.2 Seed Default Roles and Permissions**
- Create `scripts/seed.sql`:
  - Insert roles: 'user', 'admin'
  - Insert resource types: 'task', 'user', 'profile'
  - Insert permissions:
    - task: read, write, delete
    - user: read, write, delete
    - profile: read, write
  - Map user role permissions (own tasks, own profile)
  - Map admin role permissions (all permissions)
  - Create default admin user (email: admin@railtronics.com)
- Create Makefile target: `make seed`

**5.3 RBAC Models**
- Create `internal/models/role.go`:
  - Role struct
  - Permission struct (resource, action)
  - UserRole struct
- Create `internal/models/permission.go`:
  - Permission claim for JWT
  - Permission check structures

**5.4 RBAC Repository**
- Create `internal/repository/role_repository.go`:
  - `GetUserRoles(userID string) ([]Role, error)`
  - `GetRolePermissions(roleID string) ([]Permission, error)`
  - `AssignRoleToUser(userID, roleID string) error`
  - `GetRoleByName(name string) (*Role, error)`
- Create `internal/repository/permission_repository.go`:
  - `GetUserPermissions(userID string) ([]Permission, error)`
  - `GetPermissionsByRole(roleID string) ([]Permission, error)`

**5.5 RBAC Service**
- Create `internal/services/rbac_service.go`:
  - `GetUserRoles(userID string) ([]string, error)`
  - `GetUserPermissions(userID string) ([]Permission, error)`
  - `HasRole(userID, roleName string) (bool, error)`
  - `HasPermission(userID, resource, action string) (bool, error)`
  - `AssignDefaultRole(userID string) error` - assigns "user" role

**5.6 Update Registration to Assign Default Role**
- Modify `internal/services/auth_service.go`:
  - After creating user, call `AssignDefaultRole(userID)`
  - User automatically gets "user" role

**5.7 Update Login to Include Roles/Permissions**
- Modify `internal/services/auth_service.go` Login method:
  - Fetch user roles using RBAC service
  - Fetch user permissions using RBAC service
  - Include roles and permissions in JWT access token claims
  - Token should contain all permission data

**Deliverables:** Users have roles, JWT tokens contain roles and permissions, RBAC data model complete

---

### Phase 6: Authorization Middleware (Week 3-4)

**6.1 Authentication Middleware**
- Create `internal/middleware/auth.go`:
  - `AuthMiddleware() gin.HandlerFunc`
  - Extract Bearer token from Authorization header
  - Validate JWT token using jwt util
  - Extract and verify claims
  - Store userID, email, roles, permissions in Gin context
  - Return 401 if token invalid/expired

**6.2 Authorization Middleware**
- Create `internal/middleware/authorization.go`:
  - `RequirePermission(resource, action string) gin.HandlerFunc`
  - Extract permissions from context (set by AuthMiddleware)
  - Check if user has required permission
  - Return 403 Forbidden if not authorized
  - Allow admins to bypass (admin has all permissions)
  - `RequireRole(roleName string) gin.HandlerFunc`
  - Check if user has specific role

**6.3 Context Utilities**
- Create `internal/utils/context.go`:
  - `GetUserID(c *gin.Context) string`
  - `GetUserEmail(c *gin.Context) string`
  - `GetUserRoles(c *gin.Context) []string`
  - `GetUserPermissions(c *gin.Context) []Permission`
  - `IsAdmin(c *gin.Context) bool`
  - Helper functions to extract auth data from Gin context

**Deliverables:** Middleware protects endpoints, unauthorized access returns 401/403

---

### Phase 7: ABAC - Policies and Context (Week 4)

**7.1 Database Schema - ABAC Policies**
- Create migration `000004_create_policies_table.up.sql`:
  ```sql
  CREATE TABLE policies (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(100) NOT NULL,
      resource_type_id UUID REFERENCES resource_types(id),
      conditions JSONB NOT NULL,
      effect VARCHAR(10) CHECK (effect IN ('allow', 'deny')) NOT NULL,
      priority INTEGER DEFAULT 0,
      enabled BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
  );
  CREATE INDEX idx_policies_resource ON policies(resource_type_id);
  CREATE INDEX idx_policies_enabled ON policies(enabled);
  ```
- Seed example policy: users can only access their own tasks

**7.2 ABAC Models**
- Create `internal/models/policy.go`:
  - Policy struct
  - PolicyCondition struct
  - ContextAttributes map for runtime evaluation

**7.3 ABAC Repository**
- Create `internal/repository/policy_repository.go`:
  - `GetPoliciesForResource(resourceType string) ([]Policy, error)`
  - `CreatePolicy(policy *Policy) error`
  - `GetPolicyByID(id string) (*Policy, error)`

**7.4 ABAC Engine**
- Create `internal/services/abac_service.go`:
  - `EvaluatePolicy(userID, resource, action, resourceID string, context map[string]interface{}) (bool, error)`
  - Fetch applicable policies for resource
  - Sort by priority
  - Evaluate conditions against context
  - Return allow/deny decision
  - `CheckOwnership(userID, resourceOwnerID string) bool`
  - Evaluate attribute-based rules (e.g., department, time, IP)

**7.5 Authorization Service with ABAC**
- Create `internal/services/authz_service.go`:
  - Combines RBAC and ABAC
  - `Authorize(userID, resource, action, resourceID string, context map[string]interface{}) (bool, string, error)`
  - First check RBAC permissions
  - Then evaluate ABAC policies
  - Return decision with reason

**Deliverables:** ABAC policies can be evaluated, resource-level access control works

---

### Phase 8: Task Management - Database and Models (Week 4-5)

**8.1 Database Schema - Tasks Table**
- Create migration `000005_create_tasks_table.up.sql`:
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

**8.2 Task Models**
- Create `internal/models/task.go`:
  - Task struct with validation tags
  - CreateTaskRequest struct
  - UpdateTaskRequest struct
  - TaskResponse struct
  - TaskStatus enum (pending, in_progress, completed)
  - TaskPriority enum (low, medium, high)

**8.3 Task Repository**
- Create `internal/repository/task_repository.go`:
  - `CreateTask(task *Task) (*Task, error)`
  - `GetTaskByID(id string) (*Task, error)`
  - `GetTasksByOwner(ownerID string) ([]Task, error)`
  - `GetAllTasks() ([]Task, error)`
  - `UpdateTask(id string, updates *Task) (*Task, error)`
  - `DeleteTask(id string) error`
  - All queries use parameterized statements (SQL injection prevention)

**Deliverables:** Task database schema and repository complete

---

### Phase 9: Task Management - Service and Handlers (Week 5)

**9.1 Task Service**
- Create `internal/services/task_service.go`:
  - `CreateTask(userID, title, description string, ...) (*Task, error)`
  - Validate input data
  - Set owner_id to current user
  - Call repository
  - `GetTask(userID, taskID string, isAdmin bool) (*Task, error)`
  - Check ownership or admin permission
  - `GetTasks(userID string, isAdmin bool) ([]Task, error)`
  - Return only user's tasks unless admin
  - `UpdateTask(userID, taskID string, updates *Task, isAdmin bool) (*Task, error)`
  - Verify ownership before update
  - `DeleteTask(userID, taskID string, isAdmin bool) error`
  - Verify ownership or admin role

**9.2 Task Handlers**
- Create `internal/handlers/task_handler.go`:
  - `CreateTask(c *gin.Context)` - POST /v1/tasks
  - Bind request, call service, return 201
  - `GetTask(c *gin.Context)` - GET /v1/tasks/:id
  - Extract taskID from URL param
  - `ListTasks(c *gin.Context)` - GET /v1/tasks
  - Return all tasks (filtered by ownership)
  - `UpdateTask(c *gin.Context)` - PUT /v1/tasks/:id
  - Partial updates supported
  - `DeleteTask(c *gin.Context)` - DELETE /v1/tasks/:id
  - Verify permissions before deletion

**9.3 Task Routes with Authorization**
- Update `internal/api/router.go`:
  - All task routes require authentication
  - Apply permission middleware:
    - Create: `RequirePermission("task", "write")`
    - Read: `RequirePermission("task", "read")`
    - Update: `RequirePermission("task", "write")`
    - Delete: `RequirePermission("task", "delete")`

**Deliverables:** Complete task CRUD with proper authorization, users can only manage own tasks, admins can manage all

---

### Phase 10: User Profile Endpoints (Week 5)

**10.1 Profile Service**
- Create `internal/services/profile_service.go`:
  - `GetProfile(userID string) (*User, error)`
  - Return user data excluding password
  - `UpdateProfile(userID string, updates map[string]interface{}) (*User, error)`
  - Allow email updates (check uniqueness)
  - Prevent password changes via this endpoint

**10.2 Profile Handlers**
- Create `internal/handlers/profile_handler.go`:
  - `GetProfile(c *gin.Context)` - GET /v1/auth/me
  - Return current user's profile
  - Use parameterized query to prevent SQL injection
  - `UpdateProfile(c *gin.Context)` - PUT /v1/auth/me
  - Update current user's profile only

**10.3 Profile Routes**
- Update `internal/api/router.go`:
  - GET /v1/auth/me - requires authentication
  - PUT /v1/auth/me - requires authentication

**Deliverables:** Users can view and update their profile, SQL injection vulnerability prevented with parameterized queries

---

### Phase 11: Admin Endpoints (Week 6)

**11.1 Admin User Management Service**
- Create `internal/services/admin_service.go`:
  - `GetAllUsers() ([]User, error)`
  - `GetUserByID(id string) (*User, error)`
  - `UpdateUser(id string, updates map[string]interface{}) (*User, error)`
  - `DeleteUser(id string) error` - soft delete or cascade
  - `AssignUserRole(userID, roleID string) error`

**11.2 Admin Handlers**
- Create `internal/handlers/admin_handler.go`:
  - `ListUsers(c *gin.Context)` - GET /v1/admin/users
  - `GetUser(c *gin.Context)` - GET /v1/admin/users/:id
  - `UpdateUser(c *gin.Context)` - PUT /v1/admin/users/:id
  - `DeleteUser(c *gin.Context)` - DELETE /v1/admin/users/:id
  - `AssignRole(c *gin.Context)` - POST /v1/admin/users/:id/roles

**11.3 Admin Routes**
- Update `internal/api/router.go`:
  - All admin routes under `/v1/admin/*`
  - Require authentication + `RequireRole("admin")` middleware
  - Admin can manage all users and all tasks

**Deliverables:** Admins have full control over users and tasks

---

### Phase 12: Testing and Validation (Week 6-7)

**12.1 Manual Testing with Postman**
- Test registration flow
- Test login and token refresh
- Test protected endpoints without auth (expect 401)
- Test forbidden actions (user deleting other's task - expect 403)
- Test admin actions
- Test CRUD operations for tasks
- Test edge cases (invalid email, weak password, duplicate registration)
- Test SQL injection attempts on profile endpoint

**12.2 Error Handling and Validation**
- Create `internal/utils/validator.go`:
  - Email format validation
  - Password strength requirements (min 8 chars, uppercase, number)
  - UUID validation
- Create `internal/utils/errors.go`:
  - Standard error responses
  - Error codes and messages
- Update all handlers to return consistent error formats

**12.3 Logging**
- Create `internal/middleware/logging.go`:
  - Request/response logging
  - Log authentication failures
  - Log authorization denials
- Add structured logging throughout services

**Deliverables:** All endpoints tested and working correctly, proper error handling, comprehensive logs

---

### Phase 13: Documentation (Week 7)

**13.1 README Documentation**
- Update `README.md`:
  - Project overview and features
  - Architecture diagram
  - Setup instructions (dependencies, database, migrations)
  - Running the application
  - Environment variables
  - API endpoints summary
  - RBAC and ABAC explanation

**13.2 API Documentation**
- Document all endpoints:
  - Request/response formats
  - Required headers
  - Authentication requirements
  - Permission requirements
  - Example requests and responses
  - Error responses

**13.3 Database Documentation**
- Document schema design
- Entity relationship diagram
- Explain RBAC and ABAC tables
- Migration instructions

**Deliverables:** Comprehensive documentation for setup, usage, and architecture

---

### Phase 14: Docker and Deployment (Week 7)

**14.1 Docker Configuration**
- Create `Dockerfile`:
  - Multi-stage build
  - Go build stage
  - Minimal runtime image
- Create `docker-compose.yml`:
  - API service
  - PostgreSQL service
  - Network configuration
  - Volume mounts for persistence
- Create `.dockerignore`

**14.2 Deployment Scripts**
- Create `Makefile` targets:
  - `make build` - build binary
  - `make run` - run locally
  - `make test` - run tests
  - `make migrate-up` - run migrations
  - `make migrate-down` - rollback migrations
  - `make seed` - seed database
  - `make docker-up` - start Docker containers
  - `make docker-down` - stop containers

**Deliverables:** Application can be deployed using Docker Compose

---

## Stand-Out Features (Optional Enhancements)

### Postman Collection
- Export complete Postman collection
- Include all endpoints with example requests
- Pre-request scripts for token management
- Environment variables for easy switching
- Place in `postman/` directory

### Swagger API Documentation
- Install `swaggo/swag` and `swaggo/gin-swagger`
- Add Swagger annotations to handlers
- Generate swagger.json automatically
- Serve Swagger UI at `/swagger/index.html`
- Auto-update with code changes

### Pagination and Sorting
- Add pagination to GET /v1/tasks:
  - Query params: `page`, `limit` (default: page=1, limit=10)
  - Response includes: `total`, `page`, `limit`, `data`
- Add sorting:
  - Query param: `sort` (e.g., `created_at:desc`)
  - Support multiple sort fields
- Update task repository with pagination queries

### Unit Tests
- Create test files in `tests/unit/`:
  - `auth_service_test.go` - test registration, login, refresh
  - `rbac_service_test.go` - test role/permission checks
  - `abac_service_test.go` - test policy evaluation
  - `task_service_test.go` - test task operations
- Mock repositories using interfaces
- Achieve >80% code coverage
- Run with `make test`

### Integration Tests
- Create test files in `tests/integration/`:
  - `api_test.go` - test complete API flows
  - Use test database
  - Test authentication flow end-to-end
  - Test authorization scenarios
  - Test task management workflows
- Use `go test` with test containers

### End-to-End Tests with Newman/Venom
- Install Newman (Postman CLI) or Venom
- Create test suites:
  - User registration and login flow
  - Task CRUD operations with authorization
  - Admin operations
  - Error scenarios
- Run as part of CI/CD pipeline

### DRY Principles - Utility Refactoring
- Create `internal/utils/utils.go`:
  - `ParseUUID(s string) (uuid.UUID, error)`
  - `ValidateEmail(email string) bool`
  - `ParseJWT(tokenString string) (*Claims, error)`
  - `HashPassword(password string) (string, error)`
  - `ComparePassword(hash, password string) bool`
- Refactor code to use centralized utilities
- Reduce code duplication across handlers and services

---

## Key Files to Create/Modify

### Configuration
- `config/config.yaml` - application configuration
- `config/config.go` - config loader
- `.env.example` - environment variables template

### Database
- `internal/database/postgres.go` - DB connection
- `database-migrations/migrations/*.sql` - all migrations
- `scripts/seed.sql` - seed data

### Models
- `internal/models/user.go`
- `internal/models/token.go`
- `internal/models/role.go`
- `internal/models/permission.go`
- `internal/models/policy.go`
- `internal/models/task.go`

### Repositories
- `internal/repository/user_repository.go`
- `internal/repository/token_repository.go`
- `internal/repository/role_repository.go`
- `internal/repository/permission_repository.go`
- `internal/repository/policy_repository.go`
- `internal/repository/task_repository.go`

### Services
- `internal/services/auth_service.go`
- `internal/services/rbac_service.go`
- `internal/services/abac_service.go`
- `internal/services/authz_service.go`
- `internal/services/task_service.go`
- `internal/services/profile_service.go`
- `internal/services/admin_service.go`

### Handlers
- `internal/handlers/auth_handler.go`
- `internal/handlers/task_handler.go`
- `internal/handlers/profile_handler.go`
- `internal/handlers/admin_handler.go`

### Middleware
- `internal/middleware/auth.go`
- `internal/middleware/authorization.go`
- `internal/middleware/logging.go`

### Utilities
- `internal/utils/jwt.go`
- `internal/utils/password.go`
- `internal/utils/validator.go`
- `internal/utils/context.go`
- `internal/utils/errors.go`
- `internal/utils/utils.go` (stand-out feature)

### Main Application
- `cmd/api/main.go`
- `internal/api/server.go`
- `internal/api/router.go`

### Deployment
- `Dockerfile`
- `docker-compose.yml`
- `Makefile`
- `.dockerignore`

### Documentation
- `README.md`
- `docs/architecture.md`
- `docs/api.md`

---

## Success Criteria

### Core Requirements (Must Have)
- Users can register with email and password (hashed with bcrypt)
- Users can login and receive JWT access and refresh tokens (1 hour TTL)
- Refresh token endpoint generates new tokens
- RBAC implemented with "user" and "admin" roles
- ABAC policies for resource-level access control
- Permissions defined at resource:action level
- JWT tokens contain user roles and permissions
- Middleware enforces authentication and authorization
- Complete task CRUD API (create, read, update, delete)
- Users can only manage their own tasks
- Admins can manage all users and tasks
- All data persists in PostgreSQL
- SQL injection vulnerability fixed with parameterized queries
- Profile endpoints allow users to view/edit their own profile

### Stand-Out Features (Nice to Have)
- Postman collection for all endpoints
- Swagger API documentation
- Pagination and sorting on task listing
- Unit tests with good coverage
- Integration tests
- E2E tests with Newman/Venom
- Centralized utility functions (DRY)
- Docker Compose deployment

### Quality Metrics
- All endpoints respond with appropriate status codes
- Consistent error handling and messages
- Proper logging throughout application
- Clean code structure following Udacity patterns
- Comprehensive README with setup instructions
- Well-documented code
- No security vulnerabilities

### To-dos

- [ ] Create complete project structure with all directories and base files
- [ ] Implement PostgreSQL connection with health check and graceful shutdown
- [ ] Create users table migration (000001_create_users_table)
- [ ] Implement password hashing and verification utilities (bcrypt)
- [ ] Implement JWT token generation and validation utilities
- [ ] Complete user registration endpoint (repository → service → handler → route)
- [ ] Create tokens table migration (000002_create_tokens_table)
- [ ] Complete user login endpoint with JWT access and refresh tokens
- [ ] Complete refresh token endpoint to generate new access tokens
- [ ] Create RBAC tables (roles, user_roles, permissions, role_permissions)
- [ ] Create seed.sql with default roles, permissions, and admin user
- [ ] Implement role and permission repository methods
- [ ] Implement authorization service (RBAC permission checking)
- [ ] Update registration to assign default 'user' role
- [ ] Update login to embed roles and permissions in JWT
- [ ] Create authentication middleware for JWT validation
- [ ] Create authorization middleware for permission and role checking
- [ ] Create tasks table migration (000004_create_tasks_table)
- [ ] Implement task repository with parameterized queries
- [ ] Implement task service with ABAC ownership checks
- [ ] Implement all task CRUD handlers (create, read, update, delete, list)
- [ ] Implement user profile endpoints with SQL injection prevention
- [ ] Implement admin-only user management endpoints
- [ ] Review all code for SQL injection, validate all queries use parameters
- [ ] Create comprehensive Postman collection for API testing (STAND-OUT)
- [ ] Create Swagger/OpenAPI documentation (STAND-OUT)
- [ ] Add pagination and sorting to task list endpoints (STAND-OUT)
- [ ] Write unit tests for services and utilities (STAND-OUT)
- [ ] Write integration tests for API endpoints (STAND-OUT)
- [ ] Create Dockerfile and docker-compose.yml (STAND-OUT)
- [ ] Write detailed README with architecture and setup instructions (STAND-OUT)
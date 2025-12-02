## Models & Domain Flow

This folder contains the core domain models for the Taskify IAM/auth service.
They are shaped to match the SQL migrations under `database-migrations/migrations`
and the Phase 1 plan.

At a high level:

- **Users** own **tasks** and authenticate with email + password.
- **Roles** group sets of **permissions**.
- **Permissions** express what actions are allowed on which resources.
- **Tokens** track issued refresh tokens for users.

Authorization is enforced primarily through **JWT access tokens** that embed
role and permission information, derived from these models.

---

## Summary of Recent Refactor

- **User model**

  - Replaced the generic `gorm.Model` embed with explicit fields and soft delete.
  - Renamed `Password` to `PasswordHash` (still backed by the `password` column) so hashes are never serialized to JSON.
  - Added associations to `Tokens`, `Roles`, and `Tasks`, plus `TableName()` and `BeforeCreate` for UUIDs.
  - Introduced request/response DTOs: `RegisterRequest`, `LoginRequest`, `LoginResponse`.

- **Token model**

  - Made all columns explicit (including timestamps and soft delete) and aligned names with the `tokens` table.
  - Added `TableName()` and `BeforeCreate` for UUIDs.
  - Added DTOs for token exchange: `TokenPair`, `RefreshTokenRequest`.

- **Role & Permission models**

  - Added many-to-many associations (`User`–`Role` via `user_roles`, `Role`–`Permission` via `role_permissions`).
  - Added `TableName()` and `BeforeCreate` hooks for UUID generation on `Role` and `Permission`.

- **Task model**

  - Added an explicit `Owner` association to `User`.
  - Added `TableName()`, `BeforeCreate`, and DTOs `CreateTaskRequest` and `UpdateTaskRequest`.

- **Join models**
  - Added `TableName()` for `UserRole` and `RolePermission` to bind them directly to the join tables.

All of these changes keep the models consistent with the existing SQL migrations
while making relationships, IDs, and DTOs explicit for the rest of the codebase.

---

## Key Models

### User

Model: `user.go`

- **Purpose**: Represents an application user stored in the `users` table.
- **Important fields**:
  - `ID uuid.UUID`: primary key (`uuid`).
  - `Username string`: unique username.
  - `Email string`: unique email.
  - `PasswordHash string`: bcrypt hash, mapped to the `password` column, never exposed via JSON.
  - `CreatedAt`, `UpdatedAt`, `DeletedAt`: timestamps and soft delete.
- **Associations**:
  - `Tokens []Token`: 1:N with refresh tokens (via `user_id`).
  - `Roles []Role`: N:M via `user_roles`.
  - `Tasks []Task`: 1:N via `tasks.owner_id`.
- **GORM hooks & metadata**:
  - `TableName() string` → `"users"`.
  - `BeforeCreate` auto-generates a UUID when `ID` is empty.

### Token

Model: `token.go`

- **Purpose**: Represents a stored refresh token in the `tokens` table.
- **Important fields**:
  - `ID uuid.UUID`: primary key.
  - `UserID uuid.UUID`: FK to `users.id`.
  - `RefreshToken uuid.UUID`: opaque refresh token identifier.
  - `ExpiresAt time.Time`: refresh token expiry.
  - `CreatedAt`, `UpdatedAt`, `DeletedAt`: timestamps and soft delete.
- **Metadata & hooks**:
  - `TableName() string` → `"tokens"`.
  - `BeforeCreate` auto-generates a UUID for `ID`.
- **DTOs**:
  - `TokenPair`: `{ access_token, refresh_token, expires_in }` returned to clients.
  - `RefreshTokenRequest`: payload for token refresh (`refresh_token`).

### Role

Model: `role.go`

- **Purpose**: Represents a role (e.g. `user`, `admin`) in the `roles` table.
- **Important fields**:
  - `ID uuid.UUID`: primary key.
  - `Name string`: unique role name.
  - `Description string`: human-readable description.
  - `CreatedAt`, `UpdatedAt`, `DeletedAt`.
- **Associations**:
  - `Users []User`: N:M via `user_roles`.
  - `Permissions []Permission`: N:M via `role_permissions`.
- **Metadata & hooks**:
  - `TableName() string` → `"roles"`.
  - `BeforeCreate` auto-generates UUIDs for `ID`.

### Permission

Model: `permission.go`

- **Purpose**: Represents a single low-level permission in the `permissions` table.
- **Important fields**:
  - `ID uuid.UUID`: primary key.
  - `Resource string`: logical resource name (e.g. `"task"`, `"user"`, `"profile"`).
  - `Action string`: action on that resource (e.g. `"read"`, `"write"`, `"delete"`).
  - `Description string`.
  - `CreatedAt`, `UpdatedAt`, `DeletedAt`.
  - `resource + action` have a unique constraint.
- **Associations**:
  - `Roles []Role`: N:M via `role_permissions`.
- **Metadata & hooks**:
  - `TableName() string` → `"permissions"`.
  - `BeforeCreate` auto-generates UUIDs for `ID`.
- **Claims helper**:
  - `PermissionClaim` groups allowed actions by resource for embedding in JWT
    access tokens: `{ "resource": "task", "actions": ["read", "write"] }`.

### Task

Model: `task.go`

- **Purpose**: Represents a task owned by a user in the `tasks` table.
- **Important fields**:
  - `ID uuid.UUID`: primary key.
  - `Title string`: required, short summary.
  - `Description string`: optional details.
  - `Status string`: e.g. `"pending"`, `"in_progress"`, `"done"`.
  - `Priority string`: e.g. `"low"`, `"medium"`, `"high"`.
  - `OwnerID uuid.UUID`: FK to `users.id` (column `owner_id`).
  - `DueDate *time.Time`: optional due date.
  - `CreatedAt`, `UpdatedAt`, `DeletedAt`.
- **Associations**:
  - `Owner User`: the user who owns the task.
- **Metadata & hooks**:
  - `TableName() string` → `"tasks"`.
  - `BeforeCreate` auto-generates UUIDs for `ID`.
- **DTOs**:
  - `CreateTaskRequest`: payload for creating tasks.
  - `UpdateTaskRequest`: payload for partial updates.

### Join Tables

Models: `user_role.go`, `role_permission.go`

- **UserRole** (`user_roles` table):
  - Fields: `UserID`, `RoleID`, `AssignedAt`.
  - Primary key: composite (`user_id`, `role_id`).
  - Backs the `User.Roles` and `Role.Users` many-to-many relationship.
- **RolePermission** (`role_permissions` table):
  - Fields: `RoleID`, `PermissionID`, `AssignedAt`.
  - Primary key: composite (`role_id`, `permission_id`).
  - Backs the `Role.Permissions` and `Permission.Roles` many-to-many relationship.
- Both expose `TableName()` to bind explicitly to the correct tables.

---

## Auth & Authorization Flow (Conceptual)

This is the intended high-level flow that the models support.

### Registration

1. Client sends a registration payload shaped like `RegisterRequest`:
   - `email`, `password`.
2. Service validates the payload (email format, password length).
3. Password is hashed using `internal/utils/password.HashPassword`.
4. A `User` record is created:
   - `PasswordHash` is stored in the `password` column.
   - A UUID is assigned via `BeforeCreate`.
5. Optionally, the seeding and RBAC logic ensure the new user starts with a
   default role (e.g. `user`) via the `user_roles` mapping.

### Login

1. Client sends `LoginRequest` with `email` and `password`.
2. Service loads the `User` by email and verifies the password using bcrypt
   (via `CompareHashAndPassword` in utilities).
3. The service loads the user’s roles (`user_roles`) and permissions
   (`role_permissions` + `permissions`).
4. It generates:
   - A JWT access token using `internal/utils/jwt.GenerateAccessToken`, embedding:
     - `user_id`, `email`, `roles`, `is_admin`, and flattened `PermissionClaim`s.
   - An opaque refresh token stored as a `Token` row (UUID) with `ExpiresAt`.
5. The client receives a `TokenPair` (`access_token`, `refresh_token`, `expires_in`).

### Authorization on Requests

1. Client calls protected endpoints with the `access_token` in the `Authorization` header.
2. Server validates the token via `ValidateAccessToken`, recovering
   `AccessTokenClaims`.
3. Handlers/middleware check:
   - `claims.Roles` and/or
   - `claims.Permissions` (resource + allowed actions)
     to decide whether the user is allowed to perform the operation on a given
     resource.

### Refresh Token Flow

1. Client sends a `RefreshTokenRequest` with the stored `refresh_token`.
2. Service validates the token by looking up the corresponding `Token` row,
   ensuring it:
   - Exists,
   - Belongs to the user,
   - Is not expired or revoked (revocation can be added later).
3. A new access token (and possibly a new refresh token) is issued and
   persisted, returning another `TokenPair` to the client.

### Task Management

1. Authenticated users create tasks using a payload shaped like
   `CreateTaskRequest`.
2. The service creates a `Task`:
   - Sets `OwnerID` to the authenticated user’s `User.ID`.
   - Applies default `Status` and `Priority` if not provided.
3. Updates use `UpdateTaskRequest` to allow partial field updates.
4. Permission checks ensure users can only:
   - Access their own tasks, or
   - Perform admin-level actions when their roles/permissions allow it.

This README is meant as a living description of how the models fit together.
As handlers and services evolve, update this file to keep the mental model in sync.

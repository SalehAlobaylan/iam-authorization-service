## Input Validation Layer – Implementation Plan

### 1. Goals and Scope

- **Goals**
  - Ensure all external inputs (JSON bodies, path params, query params) are validated before business logic runs.
  - Provide **consistent, user-friendly error responses** for validation failures.
  - Reuse existing helpers in `backend/internal/utils/validator.go` where appropriate.
- **In scope (backend)**
  - Auth routes: **login**, **refresh token**.
  - Registration route.
  - Task routes: create, update, delete, get by ID, list by user, list all.
  - User routes: get profile (self/by ID), list users, delete user.

---

### 2. Current State Overview

- **Existing pieces**
  - `AuthRequest` and `RefreshRequest` use Gin’s `binding:"required"` tags for minimal presence checks.
  - `backend/internal/utils/validator.go` exposes:
    - `ValidateEmail(email string) error`
    - `ValidatePassword(password string) error`
    - `ValidateUUID(id string) error`
- **Gaps**
  - Most handlers (`register`, `task`, `users`) do not bind or validate request data.
  - No centralized validation error response format.
  - Custom validators are **not** wired into Gin’s validator engine.

---

### 3. Design Principles

- **Single responsibility at the boundary**
  - Handlers are responsible for **binding + validating** input and returning HTTP 4xx on failures.
  - Services assume they receive already-validated data.
- **Use Gin’s binding first**
  - Prefer `binding` tags for structural rules (required, min, max, len, oneof, etc.).
  - Use custom functions (or custom validator tags) for domain-specific rules (email, password policy, UUID).
- **Consistent error format**
  - All validation failures should return a `400 Bad Request` with a JSON body like:
    - `{"error": "validation_failed", "details": [{"field": "email", "message": "invalid email format"}]}`
- **Security**
  - Fail fast on malformed IDs (e.g., invalid UUID).
  - Avoid leaking internal details in validation error messages.

---

### 4. Validation DTOs per Route

Define or refine request structs in `backend/internal/handlers` (or a dedicated `backend/internal/api`/`dto` package if preferred) with clear `json` and `binding` tags.

#### 4.1 Auth and Refresh

- **Login (`POST /login`)**
  - Struct: `AuthRequest` (already exists; extend constraints if desired).
    - `Username string 'json:"username" binding:"required,min=3,max=50"'`
    - `Password string 'json:"password" binding:"required,min=8"'`
  - Additional checks:
    - Optionally enforce password pattern (length handled by tag, strength via helper).
- **Refresh token (`POST /refresh`)**
  - Struct: `RefreshRequest` (exists).
    - `RefreshToken string 'json:"refresh_token" binding:"required"'`
  - Additional checks:
    - Non-empty string is already enforced; no extra structure unless you encode it as UUID or JWT (then use `ValidateUUID` or JWT parse).

#### 4.2 Registration

- **Register (`POST /register`)**
  - New struct: `RegisterRequest`.
    - `Username string 'json:"username" binding:"required,min=3,max=50"'`
    - `Email string 'json:"email" binding:"required,email"'`
    - `Password string 'json:"password" binding:"required,min=8"'`
  - After binding:
    - Call `ValidateEmail(req.Email)` for stricter format if needed.
    - Call `ValidatePassword(req.Password)` to enforce policy beyond `min` length.

#### 4.3 Tasks

- **Create task (`POST /tasks`)**
  - `CreateTaskRequest`:
    - `Title string 'json:"title" binding:"required,min=1,max=255"'`
    - `Description string 'json:"description" binding:"max=2000"'`
    - `Status string 'json:"status" binding:"omitempty,oneof=pending in_progress done"'`
    - `Priority string 'json:"priority" binding:"omitempty,oneof=low medium high"'`
    - Optional `DueDate` if accepted:
      - `DueDate *time.Time 'json:"due_date" binding:"omitempty"'` (format handled by JSON + docs).
- **Update task (`PUT /tasks/:id`)**
  - Path param:
    - Validate `id` with `ValidateUUID(c.Param("id"))`.
  - Body struct: `UpdateTaskRequest` (fields optional, but validate if present):
    - `Title *string 'json:"title" binding:"omitempty,min=1,max=255"'`
    - `Description *string 'json:"description" binding:"omitempty,max=2000"'`
    - `Status *string 'json:"status" binding:"omitempty,oneof=pending in_progress done"'`
    - `Priority *string 'json:"priority" binding:"omitempty,oneof=low medium high"'`
- **Delete / Get task by ID (`DELETE/GET /tasks/:id`)**
  - Validate `:id` via `ValidateUUID`.
- **Get tasks by user (`GET /users/:id/tasks`)**
  - Validate user `:id` via `ValidateUUID`.
- **Get tasks (`GET /tasks`)**
  - If pagination/query params are added, create `ListTasksQuery` struct with `binding` tags for page, size, filters.

#### 4.4 Users

- **Get current profile (`GET /me` or similar)**
  - Typically no input body; rely on authenticated context.
- **Get user profile by ID (`GET /users/:id`)**
  - Validate `:id` using `ValidateUUID`.
- **List users (`GET /users`)**
  - If using pagination or filters, define a `ListUsersQuery` struct.
- **Delete user (`DELETE /users/:id`)**
  - Validate `:id` using `ValidateUUID`.

---

### 5. Implementation Steps

#### Step 1 – Standardize error response format

1. In `backend/internal/utils/errors.go` (or a new `response.go`), define:
   - A struct for validation error details: `type FieldError struct { Field, Message string }`.
   - A helper: `func ValidationErrorResponse(c *gin.Context, errs []FieldError)` that:
     - Sets HTTP 400.
     - Returns JSON: `{"error": "validation_failed", "details": errs}`.
2. Ensure this helper is used consistently across handlers when validation fails.

#### Step 2 – Wire up Gin’s validator and custom helpers

1. (Optional but recommended) Access Gin’s underlying validator in `main.go`:
   - `if v, ok := binding.Validator.Engine().(*validator.Validate); ok { ... }`
2. Register custom tags if needed:
   - Example: tag `uuid` that uses `ValidateUUID`.
   - Example: tag `strong_password` that uses `ValidatePassword`.
3. Update struct tags to use these custom tags where appropriate.

#### Step 3 – Add/extend request DTOs

1. For each handler (`auth.go`, `refresh.go`, `register.go`, `task.go`, `users.go`):
   - Define or refine request structs as per section 4.
   - Keep them close to handlers for now (or extract to `dto` package later).
2. Make sure all struct tags (`json`, `binding`) are correct and documented.

#### Step 4 – Apply validation in handlers

1. **AuthHandler.Token**
   - Replace placeholder logic:
     - `var req AuthRequest`
     - `if err := c.ShouldBindJSON(&req); err != nil { translate + return 400 }`
     - Optionally call `ValidatePassword(req.Password)`.
2. **RefreshHandler.Refresh**
   - Bind `RefreshRequest` and return 400 on validation error.
3. **RegisterHandler.Registration**
   - Introduce `RegisterRequest`, bind JSON, apply `ValidateEmail` and `ValidatePassword`.
4. **TaskHandler (Create/Update/Delete/Get/etc.)**
   - Create and use request structs (`CreateTaskRequest`, `UpdateTaskRequest`) with `ShouldBindJSON`.
   - Validate all path `:id` params using `ValidateUUID`.
5. **UserHandler**
   - Validate any `:id` path params with `ValidateUUID`.
   - For list endpoints with query params, use `ShouldBindQuery`.

#### Step 5 – Translate validator errors into `FieldError`s

1. Implement a small translator utility to convert `validator.ValidationErrors` into `[]FieldError`.
2. Use this translator in all handlers when `ShouldBind...` returns an error.
3. For custom helper failures (`ValidateEmail`, etc.), create `FieldError` entries manually.

#### Step 6 – Testing

1. **Unit tests for validators**
   - Test `ValidateEmail`, `ValidatePassword`, `ValidateUUID` with valid/invalid inputs.
2. **Handler tests (table-driven)**
   - For each route, test:
     - Missing required fields.
     - Invalid formats (email, UUID, status, priority).
     - Boundary values (min/max lengths).
   - Assert:
     - HTTP status is 400.
     - Response body contains expected `error` and `details` entries.
3. **Integration tests (optional but ideal)**
   - Use an in-memory or test DB and hit the HTTP routes with real requests.

---

### 6. Rollout Order

1. Implement **shared error/validation utilities** and (optionally) register custom validator tags.
2. Add/extend DTOs and validation for **Auth + Refresh + Register** (highest impact, core auth flow).
3. Add full validation for **Task** endpoints (task CRUD).
4. Add full validation for **User** endpoints.
5. Add tests alongside each group of endpoints; ensure test coverage for negative / edge cases.

---

### 7. Definition of Done

- Every handler:
  - Binds inputs via `ShouldBind...` to a struct with appropriate `binding` tags.
  - Validates path/query/body, including UUIDs and domain-specific constraints.
  - Returns consistent, documented error responses on validation failures.
- All validators and handlers have **automated tests** covering happy path and invalid inputs.
- `go test ./...` and `go build ./...` pass without errors.



# IAM-Authorization-Service

The identity and access service for the Wahb platform. Owns user registration, login, JWT issuance (HS256), refresh-token rotation, email verification, password reset, and RBAC/ABAC authorization. It is the **issuer** of the tokens that Platform-Console and Wahb-Platform attach as `Authorization: Bearer <token>` — CMS only *validates* them (shared secret).

It does **not** hold CMS business logic, content, or feeds — it is purely auth + identity.

**Port:** 4003 · **Base path:** `/api/v1` · **Stack:** Go 1.24, Gin, GORM, PostgreSQL, JWT

> Full architecture and data-model reference: [`../docs/iam-service.md`](../docs/iam-service.md). System overview: [`../docs/index.md`](../docs/index.md).

## Platform-Console Integration

Platform-Console (the admin dashboard, https://wahb-console.salehspace.dev) uses IAM for auth when `NEXT_PUBLIC_AUTH_MODE=iam`. Set `NEXT_PUBLIC_IAM_BASE_URL=http://localhost:4003` in Console's env. Console calls IAM for `login`, `register`, `refresh`, `logout`, and `GET /roles/me` (the operator's identity + roles + permissions).

## Tech Stack

- **Language:** Go 1.24 (Gin HTTP, GORM ORM)
- **Database:** PostgreSQL (Docker Postgres published on host port **5433** to avoid colliding with a local `5432`)
- **Auth:** JWT HS256 (access + refresh), bcrypt password hashing, RBAC + ABAC middleware
- **Tokens:** refresh-token rotation persisted in the `tokens` table

## Quick Start

```bash
# 1. Configure
cp .env.example .env        # edit values (JWT_SECRET, DATABASE_URL, …)

# 2. Migrate + seed defaults
make migrate-up
make seed

# 3. Run (http://localhost:4003/api/v1)
make run                    # or: go run src/main.go
```

In `development` (or with `IAM_AUTO_MIGRATE=true`) the schema **auto-migrates on boot**, and seeding runs whenever auto-migrate ran or `SEED_ON_STARTUP=true`. Production should migrate explicitly.

### Docker

```bash
make docker-up      # start all services
make docker-logs    # tail logs
make docker-down    # stop
```

### Supabase pooler note

If you use the Supabase transaction pooler (`*.pooler.supabase.com:6543`), set `DB_PREFER_SIMPLE_PROTOCOL=true` to avoid prepared-statement conflicts.

## Configuration

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DATABASE_URL` | **yes** | — | PostgreSQL DSN |
| `JWT_SECRET` | **yes** | — | HS256 signing secret — **must match CMS**. Empty/placeholder rejected in production. |
| `PORT` | no | 4003 | HTTP port |
| `HOST` | no | 0.0.0.0 | Bind host |
| `ENV` | no | development | `development`/`production` (gates auto-migrate + seed) |
| `JWT_ISSUER` | no | iam-authorization-service | Issuer claim (CMS accepts it via `JWT_ALLOWED_ISSUERS`) |
| `JWT_AUDIENCE` | no | platform-console | Audience claim |
| `DEFAULT_TENANT_ID` | no | default | Tenant claim fallback |
| `DB_PREFER_SIMPLE_PROTOCOL` | no | false | `true` for Supabase pooler |
| `CONFIG_PATH` | no | src/config/config.yaml | YAML config (env overrides win) |
| `SEED_ON_STARTUP` | no | false | Seed defaults on boot even without auto-migrate |
| `ALLOW_SEED_ENDPOINT` | no | false | Enable the admin `POST /admin/seed` route |
| `IAM_AUTO_MIGRATE` | no | (dev only) | Force auto-migrate outside dev *(in code, not in `.env.example`)* |
| `CORS_ALLOWED_ORIGINS` | no | localhost:3005,… | CSV of allowed origins |

**Email (verification + password reset) — referenced in code but missing from `.env.example`:** `SMTP_HOST`, `SMTP_PORT`, `SMTP_PASSWORD`, `EMAIL_FROM`, `EMAIL_VERIFICATION_BASE_URL`, `EMAIL_RESET_BASE_URL`, `REQUIRE_EMAIL_VERIFICATION`. Set these to enable real email delivery; the seed admin (`ADMIN_EMAIL` / `ADMIN_PASSWORD` / `ADMIN_USERNAME`) is also read from env.

> **Password policy** is temporarily relaxed to a 4-character minimum for admin registration — harden (8+) before production.

## Authentication & Authorization

- **Public** (`/api/v1/auth/*`): register, login, refresh, verify-email, resend-verification, forgot-password, reset-password.
- **Protected** (require a valid JWT): everything else. Authorization is enforced per route via `RequirePermission(resource, action)` (RBAC/ABAC) or `RequireRole("admin")`.
- **Token flow:** login returns an access token + refresh token; refresh rotates the token (persisted in `tokens`).

### Seeded roles & permissions (`make seed`)

Roles: **user**, **agent**, **editor**, **manager**, **admin** (admin gets all permissions). Permissions are `resource:action` pairs — e.g. `user:read/write/delete`, `profile:read/write`, `iam:read/write` — mapped to roles by an access-tier allow-list.

## API Surface (`/api/v1`)

### Auth (public)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/register` | Register (bcrypt) |
| POST | `/auth/login` | Login → access + refresh token |
| POST | `/auth/refresh` | Rotate refresh token |
| POST | `/auth/verify-email` · `/auth/resend-verification` | Email verification |
| POST | `/auth/forgot-password` · `/auth/reset-password` | Password reset |

### Protected (JWT)
| Method | Path | Guard | Purpose |
|--------|------|-------|---------|
| POST | `/auth/logout` | JWT | Invalidate session |
| GET | `/users` | `user:read` | List users |
| DELETE | `/users/:user_id` | `user:delete` | Delete a user |
| GET/PUT | `/users/profile` | `profile:read`/`write` | View / update own profile |
| PUT | `/users/profile/password` | `profile:write` | Change password |
| GET | `/users/profile/:user_id` | `profile:read` | View a profile |
| GET | `/roles/me` | JWT | Current user + roles + permissions |
| POST | `/roles/assign` | `admin` role | Assign a role |
| GET | `/roles/users/:user_id` | `user:read` | A user's roles |
| GET | `/iam/roles` · `/iam/permissions` · `/iam/users` | JWT | List roles / permissions / users |
| GET | `/iam/users/:user_id/roles` | JWT | A user's roles |
| PUT | `/iam/users/:user_id/roles` · `/permissions` | `iam:write` | Manage a user's roles / permissions |
| POST | `/admin/restart` · `/admin/migrations/up` · `/admin/seed` | `admin` role | Ops (seed route gated by `ALLOW_SEED_ENDPOINT`) |

### Health (public)
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Welcome |
| GET | `/health` | Liveness |

## Development

```bash
make run          # start API
make build        # compile
make test         # go test
make tidy         # go mod tidy
make migrate-up   # apply migrations
make migrate-down # roll back
make seed         # seed roles/permissions/admin
```

## Project Structure

```
src/
├── main.go         # boot: config → DB → auto-migrate/seed → server
├── config/         # env + YAML config
├── routes/         # router.go (route groups + middleware wiring)
├── middleware/     # JWT auth, RequirePermission / RequireRole (RBAC/ABAC)
├── handlers/       # Auth, User, Role, IAM, Verification, PasswordReset, Admin, Health
├── services/       # business logic
├── repository/     # data access
├── models/         # User, Role, Permission, Token, EmailVerification, PasswordReset, …
├── database/       # connection, AutoMigrate, Seed
└── utils/          # JWT, hashing, helpers
database-migrations/ # tracked SQL migrations
```

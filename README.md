# iam-authorization-service

Taskify Phase 1 backend implemented with Go, Gin, PostgreSQL, JWT, RBAC, and ABAC.

## Structure

All application code is under `src/`:

- `src/main.go`
- `src/routes`
- `src/middleware`
- `src/handlers`
- `src/services`
- `src/repository`
- `src/models`
- `src/database`
- `src/config`
- `src/utils`

## Features

- User registration with bcrypt password hashing
- Login returns JWT access token + refresh token
- Refresh token rotation with persistence in `tokens` table
- RBAC/ABAC authorization on protected endpoints
- Task CRUD with ownership rules (admin can access all)
- Seed support for default roles, permissions, and admin mapping

## Run Locally

1. Copy env file and adjust values:
   - `.env.example`
2. Run migrations:
   - `make migrate-up`
3. Seed defaults:
   - `make seed`
4. Start API:
   - `make run`

### Supabase Pooler Note

If you use Supabase transaction pooler (`*.pooler.supabase.com:6543`), enable simple protocol to avoid prepared-statement conflicts:

- `DB_PREFER_SIMPLE_PROTOCOL=true`

## Docker

- Start all services:
  - `make docker-up`
- Logs:
  - `make docker-logs`
- Stop:
  - `make docker-down`

## API Base URL

- `http://localhost:4003/api/v1`

## Local DB Port

- Docker Postgres is published on host port `5433` to avoid conflicts with existing local Postgres on `5432`.

## Main Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /users/profile`
- `GET /users`
- `DELETE /users/:user_id`
- `POST /tasks`
- `GET /tasks`
- `GET /tasks/:id`
- `PUT /tasks/:id`
- `DELETE /tasks/:id`

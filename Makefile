ifneq (,$(wildcard .env))
include .env
export
endif

DATABASE_URL ?= $(or $(DB_URL),postgres://iam:password123@localhost:5433/iam?sslmode=disable)
# Transaction poolers cannot safely hold the advisory lock used by golang-migrate.
# Supabase exposes session mode on the same host at 5432.
MIGRATION_DATABASE_URL ?= $(subst :6543/,:5432/,$(DATABASE_URL))

.PHONY: run build test tidy migrate-up migrate-down seed docker-up docker-down docker-logs

run:
	go run ./src

build:
	go build ./src

test:
	go test ./...

tidy:
	go mod tidy

migrate-up:
	@migrate -path database-migrations/migrations -database "$(MIGRATION_DATABASE_URL)" up

migrate-down:
	@migrate -path database-migrations/migrations -database "$(MIGRATION_DATABASE_URL)" down 1

seed:
	psql "$(DATABASE_URL)" -f scripts/seed.sql

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api postgres

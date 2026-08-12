ifneq (,$(wildcard .env))
include .env
export
endif

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
	@../scripts/iam-migrate.sh apply

migrate-down:
	@../scripts/iam-migrate.sh down-one

seed:
	psql "$(DATABASE_URL)" -f scripts/seed.sql

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api postgres

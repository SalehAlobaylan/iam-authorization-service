DB_URL ?= postgres://taskmanager:password123@localhost:5433/taskmanager?sslmode=disable

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
	migrate -path database-migrations/migrations -database "$(DB_URL)" up

migrate-down:
	migrate -path database-migrations/migrations -database "$(DB_URL)" down 1

seed:
	psql "$(DB_URL)" -f scripts/seed.sql

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api postgres

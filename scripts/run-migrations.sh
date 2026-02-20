#!/usr/bin/env sh
set -eu

if ! command -v migrate >/dev/null 2>&1; then
  echo "error: migrate CLI not found. Install from https://github.com/golang-migrate/migrate"
  exit 1
fi

DB_URL="${DB_URL:-postgres://taskmanager:password123@localhost:5432/taskmanager?sslmode=disable}"

migrate -path database-migrations/migrations -database "$DB_URL" up

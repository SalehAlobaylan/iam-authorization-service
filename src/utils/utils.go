package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/gofrs/uuid"
)

func GetEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func GetEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func GetEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// ParseUUID is a small helper that parses a UUID string into a uuid.UUID,
// returning a descriptive error when the format is invalid. It is used by
// repositories and services to keep UUID validation consistent.
func ParseUUID(id string) (uuid.UUID, error) {
	parsed, err := uuid.FromString(id)
	if err != nil {
		return uuid.Nil, err
	}
	return parsed, nil
}

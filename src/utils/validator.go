package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gofrs/uuid"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,50}$`)

// ValidateEmail validates email format.
func ValidateEmail(email string) error {
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidatePassword enforces a basic password policy (min length).
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	return nil
}

// ValidateUUID validates UUID format.
func ValidateUUID(id string) error {
	if _, err := uuid.FromString(id); err != nil {
		return fmt.Errorf("invalid UUID format")
	}
	return nil
}

// ValidateUsername validates a username format.
func ValidateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-50 chars and contain only letters, numbers, ., _, -")
	}
	return nil
}

func ValidateTaskStatus(status string) error {
	if status == "" {
		return nil
	}
	valid := map[string]bool{"pending": true, "in_progress": true, "completed": true}
	if !valid[status] {
		return fmt.Errorf("invalid task status")
	}
	return nil
}

func ValidateTaskPriority(priority string) error {
	if priority == "" {
		return nil
	}
	valid := map[string]bool{"low": true, "medium": true, "high": true}
	if !valid[priority] {
		return fmt.Errorf("invalid task priority")
	}
	return nil
}

func NormalizeUsername(username, email string) string {
	if username != "" {
		return strings.ToLower(username)
	}
	prefix := strings.Split(email, "@")[0]
	if prefix == "" {
		return "user"
	}
	return strings.ToLower(prefix)
}

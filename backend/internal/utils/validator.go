package utils

import (
	"fmt"
	"regexp"

	"github.com/gofrs/uuid"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

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










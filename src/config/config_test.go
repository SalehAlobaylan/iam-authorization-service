package config

import (
	"strings"
	"testing"
)

func TestValidateJWTSecret_RejectsEmpty(t *testing.T) {
	cfg := &Config{Env: "production", JWT: JWTConfig{Secret: ""}}
	if err := validateJWTSecret(cfg); err == nil {
		t.Fatal("expected error for empty JWT secret")
	}
}

func TestValidateJWTSecret_RejectsPlaceholderInProduction(t *testing.T) {
	placeholders := []string{
		"your-secret-key-change-in-production",
		"your-secret-key-change-this",
		"change-me",
		"changeme",
		"dev_jwt_secret_change_me",
	}
	for _, secret := range placeholders {
		cfg := &Config{Env: "production", JWT: JWTConfig{Secret: secret}}
		err := validateJWTSecret(cfg)
		if err == nil {
			t.Errorf("expected production to reject placeholder %q", secret)
			continue
		}
		if !strings.Contains(err.Error(), "placeholder") {
			t.Errorf("error for %q should mention placeholder; got %v", secret, err)
		}
	}
}

func TestValidateJWTSecret_AllowsPlaceholderInDevelopment(t *testing.T) {
	cfg := &Config{
		Env: "development",
		JWT: JWTConfig{Secret: "your-secret-key-change-in-production"},
	}
	if err := validateJWTSecret(cfg); err != nil {
		t.Fatalf("expected dev to tolerate placeholder, got: %v", err)
	}
}

func TestValidateJWTSecret_RejectsShortSecretInProduction(t *testing.T) {
	cfg := &Config{Env: "production", JWT: JWTConfig{Secret: "tooshort"}}
	err := validateJWTSecret(cfg)
	if err == nil {
		t.Fatal("expected production to reject a short secret")
	}
	if !strings.Contains(err.Error(), "at least 32 characters") {
		t.Errorf("error should mention minimum length; got %v", err)
	}
}

func TestValidateJWTSecret_AcceptsStrongSecretInProduction(t *testing.T) {
	cfg := &Config{
		Env: "production",
		JWT: JWTConfig{
			Secret: "a-very-strong-secret-that-is-definitely-long-enough-for-production",
		},
	}
	if err := validateJWTSecret(cfg); err != nil {
		t.Fatalf("expected strong production secret to pass, got: %v", err)
	}
}

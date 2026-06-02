package utils

import (
	"testing"
	"time"
)

const (
	testSecret = "test-secret-must-be-long-enough-to-pass-validation"
	testIssuer = "iam-authorization-service"
	testAud    = "platform-console"
	testUserID = "00000000-0000-0000-0000-000000000001"
	testEmail  = "smoke@example.com"
	testTenant = "default"
	testRole   = "admin"
)

func TestGenerateAndValidateAccessToken_RoundTrip(t *testing.T) {
	roles := []string{"admin", "manager"}
	perms := []string{"content:read", "content:write"}

	token, err := GenerateAccessToken(
		testUserID, testEmail, testTenant, testRole,
		roles, perms, testSecret, 60, testIssuer, testAud,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateAccessToken returned empty token")
	}

	claims, err := ValidateAccessToken(token, testSecret)
	if err != nil {
		t.Fatalf("ValidateAccessToken returned error: %v", err)
	}
	if claims.UserID != testUserID {
		t.Errorf("UserID: want %q got %q", testUserID, claims.UserID)
	}
	if claims.Email != testEmail {
		t.Errorf("Email: want %q got %q", testEmail, claims.Email)
	}
	if claims.TenantID != testTenant {
		t.Errorf("TenantID: want %q got %q", testTenant, claims.TenantID)
	}
	if claims.Role != testRole {
		t.Errorf("Role: want %q got %q", testRole, claims.Role)
	}
	if !claims.IsAdmin {
		t.Error("expected IsAdmin=true for admin role")
	}
	if len(claims.Permissions) != len(perms) {
		t.Errorf("Permissions count: want %d got %d", len(perms), len(claims.Permissions))
	}
	if claims.Issuer != testIssuer {
		t.Errorf("Issuer: want %q got %q", testIssuer, claims.Issuer)
	}
}

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	token, err := GenerateAccessToken(
		testUserID, testEmail, testTenant, testRole,
		[]string{"user"}, nil, testSecret, 60, testIssuer, testAud,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	if _, err := ValidateAccessToken(token, "different-secret"); err == nil {
		t.Fatal("expected error when validating with wrong secret, got nil")
	}
}

func TestValidateAccessToken_Expired(t *testing.T) {
	// TTL of 0 means the token is already expired at issuance.
	token, err := GenerateAccessToken(
		testUserID, testEmail, testTenant, testRole,
		[]string{"user"}, nil, testSecret, 0, testIssuer, testAud,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}
	// Give the system clock a moment to advance past exp.
	time.Sleep(20 * time.Millisecond)

	if _, err := ValidateAccessToken(token, testSecret); err == nil {
		t.Fatal("expected error when validating an expired token, got nil")
	}
}

func TestValidateAccessToken_Tampered(t *testing.T) {
	token, err := GenerateAccessToken(
		testUserID, testEmail, testTenant, testRole,
		[]string{"user"}, nil, testSecret, 60, testIssuer, testAud,
	)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}
	tampered := token + "tampered"
	if _, err := ValidateAccessToken(tampered, testSecret); err == nil {
		t.Fatal("expected error when validating a tampered token, got nil")
	}
}

func TestGenerateRefreshToken_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		t.Helper()
		tok, err := GenerateRefreshToken()
		if err != nil {
			t.Fatalf("GenerateRefreshToken returned error: %v", err)
		}
		if tok == "" {
			t.Fatal("GenerateRefreshToken returned empty string")
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("GenerateRefreshToken produced a duplicate: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

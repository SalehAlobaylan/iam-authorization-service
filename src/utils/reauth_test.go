package utils

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateReauthProofIsPurposeBound(t *testing.T) {
	token, err := GenerateReauthProof(testUserID, testEmail, testTenant, "feed_recovery", "plan-1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", testSecret, testIssuer)
	if err != nil || token == "" {
		t.Fatalf("GenerateReauthProof() error = %v", err)
	}
	parsed, err := jwt.ParseWithClaims(token, &ReauthProofClaims{}, func(token *jwt.Token) (interface{}, error) { return []byte(testSecret), nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("proof did not validate: %v", err)
	}
	claims := parsed.Claims.(*ReauthProofClaims)
	if claims.Purpose != "feed_recovery" || claims.PlanID != "plan-1" || claims.ManifestHash == "" || claims.ID == "" {
		t.Fatal("proof omitted binding claims")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "wahb-feed-recovery-reauth" {
		t.Fatal("proof audience is not dedicated")
	}
}

package utils

import "testing"

func TestTokenDigestIsStableAndDoesNotExposeTheCredential(t *testing.T) {
	token := "0bbdbd51-4e6c-4e8a-bbc3-2f017ce9aec1"
	digest := TokenDigest(token)

	if digest != TokenDigest(token) {
		t.Fatal("expected deterministic digest")
	}
	if digest == token || len(digest) != 64 {
		t.Fatalf("expected a SHA-256 hex digest, got %q", digest)
	}
	if digest == TokenDigest(token+"different") {
		t.Fatal("different credentials must produce different digests")
	}
}

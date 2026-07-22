package utils

import (
	"crypto/sha256"
	"encoding/hex"
)

// TokenDigest returns the stable database lookup value for an opaque,
// high-entropy, one-time credential. The original credential must only exist
// long enough to deliver it to the account holder and must never be persisted.
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

package services

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/yourusername/iam-authorization-service/src/utils"
)

// OperatorAccessSnapshot is intentionally smaller than IAMUserView. CMS needs
// only live authorization facts to decide whether a durable plan or schedule
// may continue; email, profile, credentials, and token material stay in IAM.
type OperatorAccessSnapshot struct {
	UserID        string    `json:"user_id"`
	TenantID      string    `json:"tenant_id"`
	Active        bool      `json:"active"`
	Roles         []string  `json:"roles"`
	Permissions   []string  `json:"permissions"`
	IsAdmin       bool      `json:"is_admin"`
	AccessVersion string    `json:"access_version"`
	ObservedAt    time.Time `json:"observed_at"`
}

func (s *IAMService) GetOperatorAccessSnapshot(userID, tenantID string) (OperatorAccessSnapshot, error) {
	if err := utils.ValidateUUID(userID); err != nil {
		return OperatorAccessSnapshot{}, utils.ValidationError("invalid user id")
	}
	if strings.TrimSpace(tenantID) == "" {
		return OperatorAccessSnapshot{}, utils.ValidationError("tenant id is required")
	}
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return OperatorAccessSnapshot{}, utils.NotFoundError("user not found")
	}
	if user.TenantID != tenantID {
		return OperatorAccessSnapshot{}, utils.NotFoundError("user not found")
	}
	view, err := s.userView(*user)
	if err != nil {
		return OperatorAccessSnapshot{}, err
	}
	roles := append([]string(nil), view.Roles...)
	permissions := append([]string(nil), view.Permissions...)
	sort.Strings(roles)
	sort.Strings(permissions)
	active := user.SuspendedAt == nil
	snapshot := OperatorAccessSnapshot{
		UserID:      view.ID,
		TenantID:    view.TenantID,
		Active:      active,
		Roles:       roles,
		Permissions: permissions,
		IsAdmin:     containsRole(roles, "admin"),
	}
	snapshot.AccessVersion = operatorAccessVersion(snapshot)
	snapshot.ObservedAt = time.Now().UTC()
	return snapshot, nil
}

func containsRole(roles []string, expected string) bool {
	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role), expected) {
			return true
		}
	}
	return false
}

// operatorAccessVersion intentionally contains authorization facts only.
// Profile edits, email-verification changes, and other identity metadata must
// not invalidate an otherwise current approval or schedule ownership.
func operatorAccessVersion(snapshot OperatorAccessSnapshot) string {
	parts := []string{
		"operator-access-v1", snapshot.UserID, snapshot.TenantID,
		strings.Join(snapshot.Roles, ","), strings.Join(snapshot.Permissions, ","),
	}
	if snapshot.Active {
		parts = append(parts, "active")
	} else {
		parts = append(parts, "inactive")
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

package services

import (
	"testing"
	"time"
)

func TestOperatorAccessVersionTracksAuthorizationFactsOnly(t *testing.T) {
	baseline := OperatorAccessSnapshot{
		UserID: "6d94ef4f-7875-4b8b-8b25-b774c0dc9a10", TenantID: "tenant-a", Active: true,
		Roles: []string{"admin"}, Permissions: []string{"feed:manage"}, IsAdmin: true,
		ObservedAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
	}
	first := operatorAccessVersion(baseline)
	baseline.ObservedAt = baseline.ObservedAt.Add(time.Minute)
	if observedOnly := operatorAccessVersion(baseline); observedOnly != first {
		t.Fatal("observation time must not change the authorization version")
	}

	baseline.Permissions = []string{"feed:read"}
	if changedAuthority := operatorAccessVersion(baseline); changedAuthority == first {
		t.Fatal("effective permission changes must change the authorization version")
	}
}

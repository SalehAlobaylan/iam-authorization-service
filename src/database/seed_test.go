package database

import "testing"

func TestManagerRoleCanDeleteSources(t *testing.T) {
	if !defaultRolePermissionAllowList["manager"]["source:delete"] {
		t.Fatal("manager must retain source:delete so Media Sources can delete a source")
	}
}

package services

import (
	"github.com/yourusername/iam-authorization-service/src/utils"
	"strings"
	"testing"
)

func TestEconomicsDirectoryDeniesBeforeReadingIdentities(t *testing.T) {
	service := UserService{authz: &AuthzService{}}
	for _, claims := range []*utils.AccessTokenClaims{nil, {TenantID: "a", Roles: []string{"editor"}}, {IsAdmin: true}} {
		if _, e := service.EconomicsDirectory(claims, "reader", nil); e == nil {
			t.Fatal("non-admin or missing tenant accepted")
		}
	}
	for _, q := range []string{"", strings.Repeat("x", 161)} {
		if _, e := service.EconomicsDirectory(&utils.AccessTokenClaims{TenantID: "a", IsAdmin: true}, q, nil); e == nil {
			t.Fatal("unbounded directory accepted")
		}
	}
}

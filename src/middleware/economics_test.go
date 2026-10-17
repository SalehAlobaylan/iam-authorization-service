package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/iam-authorization-service/src/config"
	"github.com/yourusername/iam-authorization-service/src/utils"
)

func TestEconomicsCounterUsesVerifiedClaimsAndClosesDeliveredEpoch(t *testing.T) {
	t.Setenv("WAHB_ENVIRONMENT_ID", "test")
	gin.SetMode(gin.TestMode)
	received := []economicsBatch{}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("missing named service credential")
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/internal/economics/collection" {
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "a", "environment": "test", "collection_enabled": true})
			return
		}
		var b economicsBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		received = append(received, b)
		w.WriteHeader(202)
	}))
	defer sink.Close()
	c := NewEconomicsCounter(config.CMSConfig{BaseURL: sink.URL, ServiceToken: "fixture"}, "a")
	c.Tick(context.Background())
	app := gin.New()
	app.Use(c.Middleware())
	account := "60fb58f6-6b9b-42bc-93dc-6f38b5bc2b14"
	app.GET("/api/v1/me", func(ctx *gin.Context) {
		if ctx.Query("signed") == "1" {
			ctx.Set(claimsContextKey, &utils.AccessTokenClaims{UserID: account, TenantID: "a"})
		}
		if ctx.Query("signed") == "other" {
			ctx.Set(claimsContextKey, &utils.AccessTokenClaims{UserID: account, TenantID: "b"})
		}
		ctx.String(200, "ok")
	})
	app.GET("/api/v1/iam/users", func(ctx *gin.Context) {
		ctx.Set(claimsContextKey, &utils.AccessTokenClaims{UserID: account, TenantID: "a", IsAdmin: true})
		ctx.String(200, "ok")
	})
	for _, path := range []string{"/api/v1/iam/users", "/api/v1/me?signed=1", "/api/v1/me?user_id=" + account, "/api/v1/me?signed=other"} {
		app.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.Close(ctx)
	if len(received) < 3 || !received[len(received)-1].Closed {
		t.Fatal("delivered counter did not close epoch")
	}
	requests := map[string]int64{}
	var sequence int64
	for _, b := range received {
		if b.Sequence != sequence+1 || b.Tenant != "a" || b.Environment != "test" {
			t.Fatal("batch scope or sequence changed", b)
		}
		sequence = b.Sequence
		for _, row := range b.Rows {
			if row.Unit == "requests" {
				requests[row.Subject] += row.Value
			}
		}
	}
	if requests["account:"+account] != 1 || requests["public"] != 1 || requests["unknown"] != 1 || requests["admin"] != 1 {
		t.Fatal("caller identity was trusted or pre-login usage merged", requests)
	}
}

func TestEconomicsCounterExpiresFailedEnvelopeAndReportsUncertainDelivery(t *testing.T) {
	t.Setenv("WAHB_ENVIRONMENT_ID", "test")
	failing := true
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "a", "environment": "test", "collection_enabled": true})
			return
		}
		if failing {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(202)
	}))
	defer sink.Close()
	c := NewEconomicsCounter(config.CMSConfig{BaseURL: sink.URL, ServiceToken: "fixture"}, "a")
	c.values[economicsKey{Subject: "public", Unit: "requests", Variant: "ok", Day: time.Now().UTC().Truncate(24 * time.Hour).Unix()}] = 2
	epoch := c.epoch
	for i := 0; i < 10; i++ {
		c.Tick(context.Background())
	}
	if c.pending != nil || c.epoch == epoch || c.lost == 0 {
		t.Fatal("unacknowledged envelope retained indefinitely")
	}
	failing = false
	c.Tick(context.Background())
	if c.sequence != 1 || c.pending != nil {
		t.Fatal("new epoch did not recover")
	}
}

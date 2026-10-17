package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/yourusername/iam-authorization-service/src/config"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Economics is a lossy bounded usage counter, never an auth or email dependency.
// Wire format is owned by CMS. No account data enters metrics labels or logs.
type economicsKey struct {
	Subject, Variant, Unit string
	Day                    int64
}
type economicsRow struct {
	Day       time.Time `json:"day"`
	Subject   string    `json:"subject"`
	Operation string    `json:"operation"`
	Unit      string    `json:"unit"`
	Variant   string    `json:"variant"`
	Value     int64     `json:"value"`
}
type economicsBatch struct {
	Closed      bool           `json:"closed"`
	Health      bool           `json:"health"`
	Version     int            `json:"schema_version"`
	Tenant      string         `json:"tenant_id"`
	Environment string         `json:"environment"`
	Epoch       string         `json:"epoch"`
	Sequence    int64          `json:"sequence"`
	StartedAt   time.Time      `json:"started_at"`
	EndedAt     time.Time      `json:"ended_at"`
	Lost        int64          `json:"lost"`
	Rows        []economicsRow `json:"rows"`
}
type EconomicsCounter struct {
	flushMu      sync.Mutex
	mu           sync.Mutex
	enabled      atomic.Bool
	values       map[economicsKey]int64
	pending      *economicsBatch
	retries      int
	pendingSince time.Time
	sequence     int64
	lost         int64
	epoch        string
	cfg          config.CMSConfig
	tenant       string
	client       *http.Client
}

func NewEconomicsCounter(cfg config.CMSConfig, tenant string) *EconomicsCounter {
	return &EconomicsCounter{values: map[economicsKey]int64{}, epoch: uuid.Must(uuid.NewV4()).String(), cfg: cfg, tenant: tenant, client: &http.Client{Timeout: 5 * time.Second}}
}
func (e *EconomicsCounter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if !e.enabled.Load() || !strings.HasPrefix(c.Request.URL.Path, "/api/v1/") {
			return
		}
		subject := "public"
		if claims, ok := GetClaims(c); ok {
			if claims.TenantID != e.tenant {
				subject = "unknown"
			} else {
				if _, err := uuid.FromString(claims.UserID); err == nil {
					subject = "account:" + claims.UserID
					if strings.HasPrefix(c.FullPath(), "/api/v1/iam/") {
						subject = "admin"
					}
				}
			}
		}
		variant := "ok"
		if c.Writer.Status() >= 400 {
			variant = "error"
		}
		day := time.Now().UTC().Truncate(24 * time.Hour).Unix()
		e.mu.Lock()
		defer e.mu.Unlock()
		add := func(unit string, n int64) {
			k := economicsKey{subject, variant, unit, day}
			if len(e.values) >= 20000 {
				if _, ok := e.values[k]; !ok {
					e.lost++
					return
				}
			}
			e.values[k] += n
		}
		add("requests", 1)
		if c.Writer.Size() > 0 {
			add("response_bytes", int64(c.Writer.Size()))
		}
		if variant == "error" {
			add("errors", 1)
		}
	}
}
func (e *EconomicsCounter) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(e.cfg.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+e.cfg.ServiceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return b, resp.StatusCode, err
}
func (e *EconomicsCounter) Tick(ctx context.Context) {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	e.tick(ctx)
}
func (e *EconomicsCounter) tick(ctx context.Context) {
	budget, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = budget
	e.mu.Lock()
	for key := range e.values {
		if time.Unix(key.Day, 0).Before(time.Now().UTC().AddDate(0, 0, -90).Truncate(24 * time.Hour)) {
			delete(e.values, key)
			e.lost++
		}
	}
	if e.pending != nil && time.Since(e.pendingSince) >= 10*time.Minute {
		e.discardPending()
	}
	e.mu.Unlock()
	b, status, err := e.request(ctx, "GET", "/internal/economics/collection", nil)
	if err != nil || status != 200 {
		e.enabled.Store(false)
		e.pauseBuffer()
		return
	}
	var policy struct {
		Tenant      string `json:"tenant_id"`
		Environment string `json:"environment"`
		Enabled     bool   `json:"collection_enabled"`
	}
	expectedEnvironment := strings.TrimSpace(os.Getenv("WAHB_ENVIRONMENT_ID"))
	if expectedEnvironment == "" {
		expectedEnvironment = "unmapped"
	}
	if json.Unmarshal(b, &policy) != nil || policy.Tenant != e.tenant || policy.Environment != expectedEnvironment {
		e.enabled.Store(false)
		e.pauseBuffer()
		return
	}
	e.enabled.Store(policy.Enabled)
	if !policy.Enabled {
		e.pauseBuffer()
		return
	}
	for batch := 0; batch < 20; batch++ {
		e.mu.Lock()
		if e.pending == nil {
			now := time.Now().UTC()
			p := &economicsBatch{Version: 1, Tenant: e.tenant, Environment: expectedEnvironment, Epoch: e.epoch, Sequence: e.sequence + 1, StartedAt: now, EndedAt: now, Rows: []economicsRow{}, Lost: e.lost}
			for k, n := range e.values {
				day := time.Unix(k.Day, 0).UTC()
				if day.Before(p.StartedAt) {
					p.StartedAt = day
				}
				p.Rows = append(p.Rows, economicsRow{day, k.Subject, "auth", k.Unit, k.Variant, n})
				delete(e.values, k)
				if len(p.Rows) == 500 {
					break
				}
			}
			if len(p.Rows) == 0 {
				p.Health = true
			}
			e.pending = p
			e.pendingSince = now
			e.retries = 0
			e.lost = 0
		}
		pending := e.pending
		e.mu.Unlock()
		if pending == nil {
			return
		}
		payload, _ := json.Marshal(pending)
		_, code, err := e.request(ctx, "POST", "/internal/economics/usage", payload)
		if err != nil || code != 202 {
			e.mu.Lock()
			e.retries++
			if e.retries >= 10 {
				e.discardPending()
			}
			e.mu.Unlock()
			return
		}
		e.mu.Lock()
		e.sequence = pending.Sequence
		e.pending = nil
		e.pendingSince = time.Time{}
		e.retries = 0
		e.mu.Unlock()
		if pending.Health {
			break
		}
	}
}
func (e *EconomicsCounter) Run(ctx context.Context) {
	if e.cfg.BaseURL == "" || e.cfg.ServiceToken == "" {
		return
	}
	e.Tick(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Tick(ctx)
		}
	}
}

// Called with mu held. Unknown acknowledgement is reported as discarded/uncertain
// counters; the previous epoch remains visibly unclosed at CMS.
func (e *EconomicsCounter) discardPending() {
	if e.pending == nil {
		return
	}
	e.lost += int64(len(e.pending.Rows))
	e.pending = nil
	e.pendingSince = time.Time{}
	e.retries = 0
	e.sequence = 0
	e.epoch = uuid.Must(uuid.NewV4()).String()
}
func (e *EconomicsCounter) pauseBuffer() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.discardPending()
	e.lost += int64(len(e.values))
	e.values = map[economicsKey]int64{}
}

// Close drains within the caller's shutdown budget. Failure leaves an unfinished
// epoch at the receiver instead of claiming that pending usage was delivered.
func (e *EconomicsCounter) Close(ctx context.Context) {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	e.tick(ctx)
	if !e.enabled.Load() || ctx.Err() != nil {
		return
	}
	e.mu.Lock()
	if e.pending != nil || len(e.values) > 0 {
		e.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	closing := economicsBatch{Version: 1, Health: true, Closed: true, Tenant: e.tenant, Environment: strings.TrimSpace(os.Getenv("WAHB_ENVIRONMENT_ID")), Epoch: e.epoch, Sequence: e.sequence + 1, StartedAt: now, EndedAt: now, Rows: []economicsRow{}}
	if closing.Environment == "" {
		closing.Environment = "unmapped"
	}
	e.mu.Unlock()
	payload, _ := json.Marshal(closing)
	if _, status, err := e.request(ctx, "POST", "/internal/economics/usage", payload); err == nil && status == 202 {
		e.mu.Lock()
		e.sequence = closing.Sequence
		e.mu.Unlock()
	}
	e.enabled.Store(false)
}

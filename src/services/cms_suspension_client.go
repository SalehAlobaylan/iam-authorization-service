package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourusername/iam-authorization-service/src/config"
)

const cmsSuspensionSyncTimeout = 5 * time.Second

// CMSSuspensionClient writes IAM's minimal enforcement mirror. It does not
// request user data from CMS and cannot make moderation decisions there.
type CMSSuspensionClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewCMSSuspensionClient(cfg config.CMSConfig) *CMSSuspensionClient {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	token := strings.TrimSpace(cfg.ServiceToken)
	if baseURL == "" || token == "" {
		return nil
	}
	return &CMSSuspensionClient{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: cmsSuspensionSyncTimeout},
	}
}

func (c *CMSSuspensionClient) Sync(ctx context.Context, userID, tenantID string, suspended bool) error {
	payload, err := json.Marshal(map[string]any{"tenant_id": tenantID, "suspended": suspended})
	if err != nil {
		return fmt.Errorf("encode suspension mirror: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/internal/auth/suspensions/"+userID, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create suspension mirror request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send suspension mirror request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("CMS suspension mirror returned %s", response.Status)
	}
	return nil
}

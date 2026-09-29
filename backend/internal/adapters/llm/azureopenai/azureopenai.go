// Package azureopenai calls an Azure OpenAI chat deployment with structured
// outputs. It narrates only; nothing it returns changes a decision.
package azureopenai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"prahari/internal/app"
)

type Config struct {
	Endpoint   string // https://<resource>.openai.azure.com
	APIKey     string
	Deployment string
	APIVersion string
	Timeout    time.Duration
}

type Client struct {
	cfg  Config
	http *http.Client
}

var _ app.LLM = (*Client)(nil)

func New(cfg Config) *Client {
	if cfg.APIVersion == "" {
		cfg.APIVersion = "2024-10-21"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}
}

func (c *Client) Enabled() bool {
	return c.cfg.Endpoint != "" && c.cfg.APIKey != "" && c.cfg.Deployment != ""
}

func (c *Client) Complete(ctx context.Context, system, user string, schema map[string]any) (string, string, error) {
	if !c.Enabled() {
		return "", "", errors.New("azure openai is not configured")
	}
	body, _ := json.Marshal(map[string]any{
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": 0.2,
		"max_tokens":  1200,
		"response_format": map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"name": "incident_brief", "strict": true, "schema": schema},
		},
	})
	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		strings.TrimRight(c.cfg.Endpoint, "/"), c.cfg.Deployment, c.cfg.APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", c.cfg.APIKey)
	res, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		// never echo the request or the key; the status is enough to act on
		return "", "", fmt.Errorf("azure openai: HTTP %d", res.StatusCode)
	}
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", fmt.Errorf("azure openai: bad response: %w", err)
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		return "", "", errors.New("azure openai: empty response")
	}
	model := out.Model
	if model == "" {
		model = c.cfg.Deployment
	}
	return out.Choices[0].Message.Content, model, nil
}

// Disabled is the LLM used when narration is switched off.
type Disabled struct{}

func (Disabled) Enabled() bool { return false }
func (Disabled) Complete(context.Context, string, string, map[string]any) (string, string, error) {
	return "", "", errors.New("llm disabled")
}

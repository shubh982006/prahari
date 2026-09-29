// Package httpapi is the REST and SSE adapter: routing, middleware,
// problem+json errors and handlers. It translates HTTP into app calls and
// holds no business logic.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"prahari/internal/domain"
)

var titles = map[string]string{
	"VALIDATION_FAILED":      "Request validation failed",
	"MALFORMED_JSON":         "Body is not valid JSON",
	"INVALID_CURSOR":         "Cursor is invalid or expired",
	"UNAUTHENTICATED":        "Authentication required",
	"TOKEN_EXPIRED":          "Token expired",
	"INVALID_CREDENTIALS":    "Invalid credentials",
	"FORBIDDEN":              "Your role cannot do this",
	"NOT_FOUND":              "Not found",
	"RUN_IN_PROGRESS":        "A run is already in progress",
	"INVALID_STATE":          "Illegal state transition",
	"ALREADY_EXISTS":         "Already exists",
	"ALREADY_SUBMITTED":      "Already submitted",
	"IDEMPOTENCY_KEY_REUSED": "Idempotency key reused with a different body",
	"NOT_FRAGILE":            "That link is not a bridge",
	"PRECONDITION_FAILED":    "Resource changed since you read it",
	"PAYLOAD_TOO_LARGE":      "Payload too large",
	"UNSUPPORTED_MEDIA_TYPE": "Unsupported media type",
	"DATASET_EMPTY":          "Dataset is empty",
	"NO_GROUND_TRUTH":        "Dataset has no ground truth",
	"RUN_NOT_SUCCEEDED":      "Run has not succeeded",
	"ADVERSARIAL_MIX":        "Adversarial and real alerts cannot mix",
	"PRECONDITION_REQUIRED":  "If-Match header required",
	"RATE_LIMITED":           "Too many requests",
	"INTERNAL":               "Unexpected error",
	"DEPENDENCY_UNAVAILABLE": "A dependency is unavailable",
}

type problem struct {
	Type        string              `json:"type"`
	Title       string              `json:"title"`
	Status      int                 `json:"status"`
	Detail      string              `json:"detail,omitempty"`
	Instance    string              `json:"instance"`
	Code        string              `json:"code"`
	RequestID   string              `json:"request_id"`
	Errors      []domain.FieldError `json:"errors,omitempty"`
	ActiveRunID string              `json:"active_run_id,omitempty"`
}

// writeError maps any error onto a problem response. Unknown errors become
// 500 INTERNAL with the request ID to quote, never with internal detail.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	de, ok := domain.AsError(err)
	if !ok {
		switch {
		case errors.Is(err, context.Canceled):
			return // client went away
		case isDBDown(err):
			de = domain.E(503, "DEPENDENCY_UNAVAILABLE", "the database is unreachable; retrying shortly")
		default:
			slog.Error("internal error", "request_id", requestID(r.Context()), "path", r.URL.Path, "err", err)
			de = domain.E(500, "INTERNAL", "unexpected error; quote the request_id when reporting it")
		}
	}
	p := problem{
		Type:      "https://prahari.dev/problems/" + strings.ReplaceAll(strings.ToLower(de.Code), "_", "-"),
		Title:     titles[de.Code],
		Status:    de.Status,
		Detail:    de.Detail,
		Instance:  r.URL.Path,
		Code:      de.Code,
		RequestID: requestID(r.Context()),
		Errors:    de.Fields,
	}
	if p.Title == "" {
		p.Title = http.StatusText(de.Status)
	}
	if de.ActiveRunID != "" {
		p.ActiveRunID = de.ActiveRunID
		w.Header().Set("Location", "/api/v1/runs/"+de.ActiveRunID)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(de.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func isDBDown(err error) bool {
	m := err.Error()
	return strings.Contains(m, "connection refused") || strings.Contains(m, "database is closed") ||
		strings.Contains(m, "failed to connect") || strings.Contains(m, "bad connection")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func validation(field, msg string) error {
	return domain.Validation(domain.FieldError{Field: field, Message: msg})
}

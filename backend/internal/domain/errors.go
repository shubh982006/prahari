package domain

import (
	"errors"
	"fmt"
)

// Error is a failure with a stable machine-readable code. The HTTP layer maps
// codes onto RFC 9457 problem responses; the UI switches on Code.
type Error struct {
	Code        string
	Status      int
	Detail      string
	Fields      []FieldError
	ActiveRunID string
}

type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func E(status int, code, format string, args ...any) *Error {
	return &Error{Code: code, Status: status, Detail: fmt.Sprintf(format, args...)}
}

func NotFound(what string) *Error { return E(404, "NOT_FOUND", "%s not found", what) }

func Validation(fields ...FieldError) *Error {
	return &Error{Code: "VALIDATION_FAILED", Status: 400,
		Detail: fmt.Sprintf("%d field(s) invalid", len(fields)), Fields: fields}
}

func Forbidden(detail string) *Error { return E(403, "FORBIDDEN", "%s", detail) }

func Conflict(code, format string, args ...any) *Error { return E(409, code, format, args...) }

func Unprocessable(code, format string, args ...any) *Error { return E(422, code, format, args...) }

// ErrNotFound is returned by stores for a missing row.
var ErrNotFound = errors.New("not found")

func AsError(err error) (*Error, bool) {
	var de *Error
	if errors.As(err, &de) {
		return de, true
	}
	return nil, false
}

package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"prahari/internal/domain"
)

// Cursors are opaque, signed keyset positions. A tampered or foreign cursor
// is INVALID_CURSOR rather than a silently wrong page.

func (a *App) EncodeCursor(v any) string {
	b, _ := json.Marshal(v)
	mac := hmac.New(sha256.New, a.JWTSecret)
	mac.Write([]byte("cursor|"))
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])
}

func (a *App) DecodeCursor(s string, v any) error {
	bad := domain.E(400, "INVALID_CURSOR", "cursor is invalid or expired; restart from the first page")
	body, sig, ok := strings.Cut(s, ".")
	if !ok {
		return bad
	}
	b, err1 := base64.RawURLEncoding.DecodeString(body)
	got, err2 := base64.RawURLEncoding.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return bad
	}
	mac := hmac.New(sha256.New, a.JWTSecret)
	mac.Write([]byte("cursor|"))
	mac.Write(b)
	if !hmac.Equal(got, mac.Sum(nil)[:12]) {
		return bad
	}
	if json.Unmarshal(b, v) != nil {
		return bad
	}
	return nil
}

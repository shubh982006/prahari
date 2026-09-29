package app

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"prahari/internal/domain"
)

const (
	TokenLifetime    = time.Hour
	pbkdf2Iterations = 210_000
)

// HashPassword returns pbkdf2-sha256$<iterations>$<salt>$<key>.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key))
}

func VerifyPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err1 := hex.DecodeString(parts[2])
	want, err2 := hex.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash makes a login for an unknown user cost the same as a wrong
// password, so timing cannot enumerate accounts.
var dummyHash = HashPassword("not-a-real-password")

type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
	Jti  string `json:"jti"`
}

func (a *App) Login(ctx context.Context, username, password string) (string, User, error) {
	u, err := a.Store.UserByUsername(ctx, username)
	if err != nil {
		VerifyPassword(dummyHash, password)
		return "", User{}, domain.E(401, "INVALID_CREDENTIALS", "username or password is incorrect")
	}
	if !VerifyPassword(u.PasswordHash, password) {
		return "", User{}, domain.E(401, "INVALID_CREDENTIALS", "username or password is incorrect")
	}
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	now := a.now()
	tok := a.SignToken(Claims{Sub: u.UserID, Role: u.Role, Iat: now.Unix(), Exp: now.Add(TokenLifetime).Unix(), Jti: hex.EncodeToString(jti)})
	return tok, u, nil
}

var b64 = base64.RawURLEncoding

func (a *App) SignToken(c Claims) string {
	header := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(c)
	signing := header + "." + b64.EncodeToString(body)
	mac := hmac.New(sha256.New, a.JWTSecret)
	mac.Write([]byte(signing))
	return signing + "." + b64.EncodeToString(mac.Sum(nil))
}

// VerifyToken checks signature, algorithm and expiry.
func (a *App) VerifyToken(tok string) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c, domain.E(401, "UNAUTHENTICATED", "malformed token")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return c, domain.E(401, "UNAUTHENTICATED", "malformed token")
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hb, &h) != nil || h.Alg != "HS256" {
		return c, domain.E(401, "UNAUTHENTICATED", "unsupported token algorithm")
	}
	mac := hmac.New(sha256.New, a.JWTSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return c, domain.E(401, "UNAUTHENTICATED", "invalid token signature")
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil || json.Unmarshal(body, &c) != nil {
		return c, domain.E(401, "UNAUTHENTICATED", "malformed token")
	}
	if a.now().Unix() >= c.Exp {
		return c, domain.E(401, "TOKEN_EXPIRED", "token expired; sign in again")
	}
	return c, nil
}

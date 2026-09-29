package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"prahari/internal/app"
	"prahari/internal/domain"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyUser
)

type principal struct {
	UserID string
	Role   string
}

func requestID(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}

func userOf(ctx context.Context) principal {
	p, _ := ctx.Value(keyUser).(principal)
	return p
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = crockford[int(b[i])%32]
	}
	return "req_" + string(b)
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(s int) {
	w.status = s
	w.ResponseWriter.WriteHeader(s)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Flush lets SSE handlers flush through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// base wraps every request: request ID, recovery, structured access log and
// metrics.
func (s *Server) base(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), keyRequestID, id)
		r = r.WithContext(ctx)
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "request_id", id, "panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				writeError(sw, r, fmt.Errorf("panic: %v", rec))
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			d := time.Since(start)
			s.metrics.observeRequest(route, sw.status, d)
			if !strings.HasPrefix(r.URL.Path, "/healthz") && !strings.HasPrefix(r.URL.Path, "/metrics") {
				s.log.Info("http", "request_id", id, "method", r.Method, "path", r.URL.Path, "route", route,
					"status", sw.status, "ms", d.Milliseconds(), "user", userOf(r.Context()).UserID)
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

// cors allows the configured frontend origins; the SPA normally reaches the
// API through nginx on the same origin, where this is a no-op.
func (s *Server) cors(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range s.cfg.CORSOrigins {
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && allowed[o] {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", o)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, If-Match, If-None-Match, Last-Event-ID")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Expose-Headers", "ETag, Location, X-Request-ID, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After")
			h.Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type route struct {
	public bool   // no token needed
	lead   bool   // requires the lead role
	sse    bool   // accepts ?access_token= because EventSource cannot set headers
	limit  string // rate-limit class
}

// guard authenticates, authorises and rate-limits one route.
func (s *Server) guard(rt route, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rt.public {
			tok := ""
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				tok = strings.TrimPrefix(auth, "Bearer ")
			} else if rt.sse {
				tok = r.URL.Query().Get("access_token")
			}
			if tok == "" {
				writeError(w, r, domain.E(401, "UNAUTHENTICATED", "send Authorization: Bearer <token>"))
				return
			}
			c, err := s.app.VerifyToken(tok)
			if err != nil {
				writeError(w, r, err)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), keyUser, principal{UserID: c.Sub, Role: c.Role}))
			if rt.lead && c.Role != "lead" {
				writeError(w, r, domain.Forbidden("this action requires the lead role"))
				return
			}
		}
		class, key := rt.limit, userOf(r.Context()).UserID
		if class == "" {
			class = "default"
		}
		if class == "login" || key == "" {
			key = clientIP(r)
		}
		if !s.limiter.allow(w, class, key) {
			writeError(w, r, domain.E(429, "RATE_LIMITED", "slow down; retry after the Retry-After interval"))
			return
		}
		h(w, r)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- rate limiting ----------

// limiter is an in-process token bucket per (class, key). On multi-instance
// Postgres deployments the effective limit multiplies by replica count; that
// is a documented limitation, not a silent one.
type limiter struct {
	mu      sync.Mutex
	classes map[string]int // requests per minute
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter {
	return &limiter{
		classes: map[string]int{"login": 10, "narrative": 10, "campaign": 6, "default": 300},
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

func (l *limiter) allow(w http.ResponseWriter, class, key string) bool {
	perMin := l.classes[class]
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	k := class + "|" + key
	b, ok := l.buckets[k]
	if !ok {
		b = &bucket{tokens: float64(perMin), last: now}
		l.buckets[k] = b
		if len(l.buckets) > 50_000 {
			l.buckets = map[string]*bucket{k: b}
		}
	}
	rate := float64(perMin) / 60
	b.tokens = math.Min(float64(perMin), b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(perMin))
	if b.tokens < 1 {
		wait := int(math.Ceil((1 - b.tokens) / rate))
		h.Set("RateLimit-Remaining", "0")
		h.Set("RateLimit-Reset", strconv.Itoa(wait))
		h.Set("Retry-After", strconv.Itoa(wait))
		return false
	}
	b.tokens--
	h.Set("RateLimit-Remaining", strconv.Itoa(int(b.tokens)))
	h.Set("RateLimit-Reset", strconv.Itoa(int(math.Ceil((float64(perMin)-b.tokens)/rate))))
	return true
}

// ---------- bodies ----------

const maxJSONBody = 1 << 20

// decode reads a JSON body strictly: unknown fields are a validation error,
// not silently ignored.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return domain.E(415, "UNSUPPORTED_MEDIA_TYPE", "send Content-Type: application/json")
	}
	body := http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &mbe):
			return domain.E(413, "PAYLOAD_TOO_LARGE", "JSON bodies are limited to 1 MB")
		case errors.As(err, &te):
			return validation("body."+te.Field, "must be "+jsonType(te.Type.String()))
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return validation("body."+strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`), "unknown field")
		case errors.Is(err, io.EOF):
			return domain.E(400, "MALFORMED_JSON", "request body is empty")
		default:
			return domain.E(400, "MALFORMED_JSON", "request body is not valid JSON")
		}
	}
	return nil
}

func jsonType(t string) string {
	switch {
	case strings.Contains(t, "int"), strings.Contains(t, "float"):
		return "a number"
	case t == "string" || strings.HasSuffix(t, "string"):
		return "a string"
	case t == "bool":
		return "a boolean"
	case strings.HasPrefix(t, "[]"):
		return "an array"
	}
	return "an object"
}

// ---------- idempotency ----------

const idempotencyWindow = 24 * time.Hour

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (r *recorder) WriteHeader(s int) { r.status = s; r.ResponseWriter.WriteHeader(s) }
func (r *recorder) Write(b []byte) (int, error) {
	r.buf.Write(b)
	return r.ResponseWriter.Write(b)
}

// idempotent replays the stored response for a repeated Idempotency-Key with
// the same body, and rejects the same key with a different body.
func (s *Server) idempotent(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			h(w, r)
			return
		}
		if len(key) > 128 {
			writeError(w, r, validation("header.Idempotency-Key", "at most 128 characters"))
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
		if err != nil {
			writeError(w, r, domain.E(413, "PAYLOAD_TOO_LARGE", "JSON bodies are limited to 1 MB"))
			return
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		user := userOf(r.Context()).UserID
		route := r.Method + " " + r.URL.Path
		prev, ok, err := s.app.Store.GetIdempotent(r.Context(), user, route, key, time.Now().Add(-idempotencyWindow))
		if err != nil {
			writeError(w, r, err)
			return
		}
		if ok {
			if prev.BodyHash != hash {
				writeError(w, r, domain.Conflict("IDEMPOTENCY_KEY_REUSED", "this Idempotency-Key was used with a different body; generate a new key"))
				return
			}
			for k, v := range prev.Headers {
				w.Header().Set(k, v)
			}
			w.Header().Set("Idempotent-Replayed", "true")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(prev.Status)
			_, _ = w.Write(prev.Body)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := &recorder{ResponseWriter: w}
		h(rec, r)
		if rec.status >= 200 && rec.status < 300 {
			hdr := map[string]string{}
			if loc := w.Header().Get("Location"); loc != "" {
				hdr["Location"] = loc
			}
			_ = s.app.Store.PutIdempotent(context.WithoutCancel(r.Context()), user, route, key,
				app.IdempotentResponse{BodyHash: hash, Status: rec.status, Body: rec.buf.Bytes(), Headers: hdr}, time.Now())
		}
	}
}

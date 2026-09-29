package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"prahari/internal/core/receipt"
)

// GenesisHash is prev_hash for the first audit entry.
var GenesisHash = strings.Repeat("0", 64)

// AuditTime truncates to microseconds, the precision both dialects store, so
// a hash computed at append time verifies after a round trip.
func AuditTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// AuditHash is the chain function (api-contract §16):
//
//	hash_n = hex(SHA-256(prev || "|" || ts(RFC3339Nano) || "|" || actor || "|" ||
//	                     action || "|" || subject || "|" || canonical_json(payload)))
//
// Canonical JSON is recomputed from the payload so that Postgres JSONB's key
// reordering cannot change the hash.
func AuditHash(prev string, ts time.Time, actor, action, subject string, payload json.RawMessage) string {
	var generic any
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	_ = json.Unmarshal(payload, &generic)
	var b strings.Builder
	b.WriteString(prev)
	b.WriteByte('|')
	b.WriteString(AuditTime(ts).Format(time.RFC3339Nano))
	b.WriteByte('|')
	b.WriteString(actor)
	b.WriteByte('|')
	b.WriteString(action)
	b.WriteByte('|')
	b.WriteString(subject)
	b.WriteByte('|')
	b.Write(receipt.CanonicalJSON(generic))
	s := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(s[:])
}

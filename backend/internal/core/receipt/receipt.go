// Package receipt computes the determinism receipt: input, config and output
// hashes to the byte specification in design §10.1.
//
// Three rules, the first being where determinism usually dies:
//
//	D1  every hash input is built from an explicitly sorted slice; never range
//	    over a map into a hash
//	D2  floats are hashed as FormatFloat(v, 'f', 2, 64), never as raw bits
//	D3  canonical JSON is sorted keys and no insignificant whitespace
//
// \x1f (unit separator) and \x1e (record separator) cannot appear in an ID,
// so no field can be smuggled across a boundary. The "v1\n" prefix versions
// the scheme.
package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"prahari/internal/domain"
)

const Scheme = "v1"

// CanonicalJSON re-encodes v through a generic value so that map keys sort and
// struct field order cannot leak into a hash.
func CanonicalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		panic(err)
	}
	out, _ := json.Marshal(generic)
	return out
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func Sum(b []byte) string { return sum(b) }

// InputHash covers the alerts the run loaded, sorted by (ts, id).
func InputHash(alerts []domain.Alert) string {
	as := make([]domain.Alert, len(alerts))
	copy(as, alerts)
	sort.SliceStable(as, func(i, j int) bool {
		if !as[i].TS.Equal(as[j].TS) {
			return as[i].TS.Before(as[j].TS)
		}
		return as[i].ID < as[j].ID
	})
	var b strings.Builder
	b.WriteString(Scheme + "\n")
	for _, a := range as {
		ent := sha256.Sum256(CanonicalJSON(a.Entities.Normalized()))
		b.WriteString(a.ID)
		b.WriteByte(0x1f)
		b.WriteString(a.TS.UTC().Format(time.RFC3339Nano))
		b.WriteByte(0x1f)
		b.WriteString(a.RuleID)
		b.WriteByte(0x1f)
		b.WriteString(string(a.Severity))
		b.WriteByte(0x1f)
		b.WriteString(a.TechniqueID)
		b.WriteByte(0x1f)
		b.WriteString(hex.EncodeToString(ent[:]))
		b.WriteByte(0x1e)
	}
	return sum([]byte(b.String()))
}

// ConfigHash covers everything besides the alerts that can change the output:
// engine parameters, versions, and fingerprints of the CMDB, rule statistics
// and active suppressions. Without those last three, two runs could share an
// input and config hash yet differ in output, and the receipt would lie.
func ConfigHash(config map[string]any) string {
	return sum(append([]byte(Scheme+"\n"), CanonicalJSON(config)...))
}

// OutputHash covers each incident's identity, priority, risk, cohesion and
// membership, sorted by incident ID.
func OutputHash(incidents []domain.Incident) string {
	incs := make([]domain.Incident, len(incidents))
	copy(incs, incidents)
	sort.Slice(incs, func(i, j int) bool { return incs[i].ID < incs[j].ID })
	var b strings.Builder
	b.WriteString(Scheme + "\n")
	for _, inc := range incs {
		ids := append([]string(nil), inc.AlertIDs...)
		sort.Strings(ids)
		b.WriteString(inc.ID)
		b.WriteByte(0x1f)
		b.WriteString(inc.Priority)
		b.WriteByte(0x1f)
		b.WriteString(strconv.FormatFloat(inc.Risk, 'f', 2, 64))
		b.WriteByte(0x1f)
		b.WriteString(inc.Cohesion)
		b.WriteByte(0x1f)
		b.WriteString(strings.Join(ids, ","))
		b.WriteByte(0x1e)
	}
	return sum([]byte(b.String()))
}

// AssetsHash fingerprints the CMDB as the run saw it.
func AssetsHash(assets map[string]domain.Asset) string {
	names := make([]string, 0, len(assets))
	for h := range assets {
		names = append(names, h)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, h := range names {
		a := assets[h]
		dc := append([]string(nil), a.DataClasses...)
		sort.Strings(dc)
		b.WriteString(h + "\x1f" + strconv.Itoa(a.Criticality) + "\x1f" + strings.Join(dc, ",") + "\x1e")
	}
	return sum([]byte(b.String()))
}

// RuleStatsHash fingerprints rule precision as the run saw it.
func RuleStatsHash(stats map[string]domain.RuleStat) string {
	ids := make([]string, 0, len(stats))
	for id := range stats {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		s := stats[id]
		b.WriteString(id + "\x1f" + strconv.FormatFloat(s.Alpha, 'f', 4, 64) + "\x1f" + strconv.FormatFloat(s.Beta, 'f', 4, 64) + "\x1e")
	}
	return sum([]byte(b.String()))
}

// SuppressionsHash fingerprints the suppressions active for a run.
func SuppressionsHash(sup []domain.Suppression, at time.Time) string {
	var keys []string
	for _, s := range sup {
		if s.ExpiresAt == nil || s.ExpiresAt.After(at) {
			keys = append(keys, s.RuleID+"\x1f"+s.EntityKey)
		}
	}
	sort.Strings(keys)
	return sum([]byte(strings.Join(keys, "\x1e")))
}

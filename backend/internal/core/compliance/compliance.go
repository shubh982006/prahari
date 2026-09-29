// Package compliance evaluates the breach trigger and builds regulator drafts.
//
// Trigger: priority P1/P2, reaches stage 5–6, and touches an asset tagged pii
// or financial. Three tracks run from detected_at, which the caller freezes
// the first time an incident triggers and never recomputes.
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"prahari/internal/core/entity"
	"prahari/internal/domain"
)

const Disclaimer = "Auto-generated draft for review by the organisation. Not legal advice. Not submitted."

type Track struct {
	Name         string
	Authority    string
	Basis        string
	Offset       time.Duration
	DeadlineKind string
}

var Tracks = []Track{
	{"certin", "CERT-In", "CERT-In Directions (28 Apr 2022): report within 6 hours of noticing", 6 * time.Hour, "statutory"},
	{"dpdp_intimation", "Data Protection Board of India", "DPDP Rules 2025, Rule 7: intimate without delay (internal SLA 1 h)", time.Hour, "internal_sla"},
	{"dpdp_report", "Data Protection Board of India", "DPDP Rules 2025, Rule 7: detailed report within 72 hours", 72 * time.Hour, "statutory"},
}

func TrackByName(name string) (Track, bool) {
	for _, t := range Tracks {
		if t.Name == name {
			return t, true
		}
	}
	return Track{}, false
}

// Trigger returns the breach trigger for an incident, or nil.
func Trigger(priority string, maxStage int, hosts []string, assets map[string]domain.Asset) *domain.BreachTrigger {
	if priority != "P1" && priority != "P2" {
		return nil
	}
	if maxStage < 5 {
		return nil
	}
	var hit []string
	classes := map[string]bool{}
	for _, h := range hosts {
		a, ok := assets[h]
		if !ok || !a.Sensitive() {
			continue
		}
		hit = append(hit, h)
		for _, c := range a.DataClasses {
			classes[c] = true
		}
	}
	if len(hit) == 0 {
		return nil
	}
	sort.Strings(hit)
	dc := make([]string, 0, len(classes))
	for c := range classes {
		dc = append(dc, c)
	}
	sort.Strings(dc)
	return &domain.BreachTrigger{Priority: priority, MaxStage: maxStage, Assets: hit, DataClasses: dc}
}

// Evidence is what a draft is built from: the incident as committed and its
// member alerts, never model output.
type Evidence struct {
	CaseID     string
	Incident   domain.Incident
	Alerts     []domain.Alert // member alerts, time order
	Assets     map[string]domain.Asset
	DetectedAt time.Time
	Techniques map[string]string // technique ID → name
}

// Hash fingerprints the evidence so a draft can be tied to exactly what it saw.
func (e Evidence) Hash() string {
	ids := append([]string(nil), e.Incident.AlertIDs...)
	sort.Strings(ids)
	b, _ := json.Marshal(map[string]any{
		"incident_id": e.Incident.ID,
		"detected_at": e.DetectedAt.UTC().Format(time.RFC3339Nano),
		"alerts":      ids,
		"trigger":     e.Incident.Breach,
	})
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type view struct {
	occurred     time.Time
	systems      []map[string]any
	externalIPs  []string
	accounts     []string
	hashes       []string
	techniques   []string
	vector       string
	incidentType string
	dataClasses  []string
}

func build(e Evidence) view {
	v := view{occurred: e.Incident.FirstSeen}
	ipsByHost := map[string]map[string]bool{}
	ext, acc, hsh := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range e.Alerts {
		for _, u := range a.Entities.Users {
			acc[u] = true
		}
		for _, h := range a.Entities.Hashes {
			hsh[h] = true
		}
		for _, ip := range a.Entities.IPs {
			if entity.IsExternal(ip) {
				ext[ip] = true
			} else if len(a.Entities.Hosts) == 1 {
				h := a.Entities.Hosts[0]
				if ipsByHost[h] == nil {
					ipsByHost[h] = map[string]bool{}
				}
				ipsByHost[h][ip] = true
			}
		}
	}
	for _, h := range e.Incident.Assets {
		as, ok := e.Assets[h]
		role := "unknown"
		if ok {
			role = as.Role
		}
		v.systems = append(v.systems, map[string]any{"hostname": h, "role": role, "ips": keys(ipsByHost[h])})
	}
	v.externalIPs, v.accounts, v.hashes = keys(ext), keys(acc), keys(hsh)
	for _, t := range e.Incident.Techniques {
		name := t.Name
		if name == "" {
			name = e.Techniques[t.TechniqueID]
		}
		v.techniques = append(v.techniques, strings.TrimSpace(t.TechniqueID+" "+name))
	}
	if e.Incident.Breach != nil {
		v.dataClasses = e.Incident.Breach.DataClasses
	}
	v.vector = vector(e)
	v.incidentType = incidentType(e)
	return v
}

func vector(e Evidence) string {
	if len(e.Incident.ChainIDs) == 0 {
		return "Not determined from available alerts"
	}
	first := e.Incident.ChainIDs[0]
	for _, a := range e.Alerts {
		if a.ID == first {
			return fmt.Sprintf("%s (first observed %s)", a.RuleName, a.TS.UTC().Format(time.RFC3339))
		}
	}
	return "Not determined from available alerts"
}

func incidentType(e Evidence) string {
	var parts []string
	has := func(stage int) bool {
		for _, s := range e.Incident.Stages {
			if s == stage {
				return true
			}
		}
		return false
	}
	if has(1) || has(3) || has(4) {
		parts = append(parts, "Unauthorised access to IT systems")
	}
	for _, t := range e.Incident.Techniques {
		if t.Stage == 6 && strings.Contains(strings.ToLower(t.Tactic), "impact") {
			parts = append(parts, "Disruption or destruction of data")
			break
		}
	}
	if has(6) {
		parts = append(parts, "data exfiltration")
	}
	if len(parts) == 0 {
		parts = append(parts, "Suspected compromise")
	}
	return strings.Join(parts, "; ")
}

// Draft builds the fields for one track.
func Draft(track string, e Evidence) map[string]any {
	v := build(e)
	affected := strings.Join(e.Incident.Assets, ", ")
	classes := strings.Join(v.dataClasses, ", ")
	switch track {
	case "certin":
		return map[string]any{
			"incident_type":    v.incidentType,
			"occurred_at":      v.occurred.UTC().Format(time.RFC3339),
			"detected_at":      e.DetectedAt.UTC().Format(time.RFC3339),
			"affected_systems": v.systems,
			"attack_vector":    v.vector,
			"techniques":       v.techniques,
			"indicators":       map[string]any{"external_ips": v.externalIPs, "hashes": v.hashes, "accounts": v.accounts},
			"actions_taken":    actions(e),
			"contact":          "SOC Lead, <organisation>",
		}
	case "dpdp_intimation":
		return map[string]any{
			"description":   e.Incident.Headline,
			"nature":        v.incidentType,
			"extent":        fmt.Sprintf("Systems holding %s data: %s. Records affected: to be determined by investigation.", orNone(classes), affected),
			"timing":        fmt.Sprintf("Activity from %s; detected %s", v.occurred.UTC().Format(time.RFC3339), e.DetectedAt.UTC().Format(time.RFC3339)),
			"location":      affected,
			"likely_impact": likelyImpact(v.dataClasses),
		}
	case "dpdp_report":
		return map[string]any{
			"facts":                 fmt.Sprintf("%d correlated alerts across %d kill-chain stages between %s and %s.", len(e.Alerts), e.Incident.ForwardStages, e.Incident.FirstSeen.UTC().Format(time.RFC3339), e.Incident.LastSeen.UTC().Format(time.RFC3339)),
			"circumstances":         e.Incident.Headline,
			"reasons":               v.vector,
			"mitigation":            actions(e),
			"findings":              fmt.Sprintf("Observed techniques: %s.", strings.Join(v.techniques, "; ")),
			"remedial_steps":        []string{"Reset credentials of affected accounts", "Review access to affected systems", "Preserve logs for 180 days per CERT-In Directions"},
			"data_principal_notice": fmt.Sprintf("We detected unauthorised activity on systems that hold your %s data. We are investigating and will inform you of any action you should take.", orNone(classes)),
		}
	}
	return nil
}

func actions(e Evidence) []string {
	out := []string{"Incident triaged in Prahari"}
	v := build(e)
	if len(v.accounts) > 0 {
		out = append(out, "Account disable recommended")
	}
	if len(v.externalIPs) > 0 {
		out = append(out, "Source IP block recommended")
	}
	return out
}

func likelyImpact(classes []string) string {
	var parts []string
	for _, c := range classes {
		switch c {
		case "pii":
			parts = append(parts, "exposure of personal data of data principals")
		case "financial":
			parts = append(parts, "exposure of financial records")
		}
	}
	if len(parts) == 0 {
		return "To be assessed"
	}
	return strings.Join(parts, "; ")
}

// Markdown renders a draft for copy-paste into an email.
func Markdown(caseID, track string, fields map[string]any, generated time.Time, evidenceHash string) string {
	t, _ := TrackByName(track)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s draft: %s\n\n", t.Authority, caseID)
	fmt.Fprintf(&b, "_%s_\n\n", Disclaimer)
	fmt.Fprintf(&b, "- Basis: %s\n- Generated: %s\n- Evidence: `%s`\n\n", t.Basis, generated.UTC().Format(time.RFC3339), evidenceHash)
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(&b, "## %s\n\n", strings.ReplaceAll(k, "_", " "))
		writeValue(&b, fields[k])
		b.WriteString("\n")
	}
	return b.String()
}

func writeValue(b *strings.Builder, v any) {
	switch x := v.(type) {
	case []string:
		for _, s := range x {
			fmt.Fprintf(b, "- %s\n", s)
		}
	case []any:
		if len(x) == 0 {
			b.WriteString("_none_\n")
		}
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				b.WriteString("- " + inline(m) + "\n")
			} else {
				fmt.Fprintf(b, "- %v\n", item)
			}
		}
	case []map[string]any:
		for _, m := range x {
			b.WriteString("- " + inline(m) + "\n")
		}
	case map[string]any:
		names := make([]string, 0, len(x))
		for k := range x {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(b, "- **%s**: %s\n", strings.ReplaceAll(k, "_", " "), plain(x[k]))
		}
	default:
		fmt.Fprintf(b, "%v\n", x)
	}
}

// inline renders one object as "key: value · key: value".
func inline(m map[string]any) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, strings.ReplaceAll(k, "_", " ")+": "+plain(m[k]))
	}
	return strings.Join(parts, " · ")
}

func plain(v any) string {
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			return "none"
		}
		s := make([]string, len(x))
		for i, e := range x {
			s[i] = fmt.Sprint(e)
		}
		return strings.Join(s, ", ")
	case []string:
		if len(x) == 0 {
			return "none"
		}
		return strings.Join(x, ", ")
	}
	return fmt.Sprint(v)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "sensitive"
	}
	return s
}

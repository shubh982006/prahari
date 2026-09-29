// Package evade generates attackers who know how Prahari works. Each strategy
// takes a base dataset with planted scenarios and an evasion budget β in
// [0,1], and returns a mutated copy plus updated ground truth. Generators are
// seeded and pure: same inputs, same adversary, so the curve reproduces.
package evade

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"

	"prahari/internal/core/entity"
	"prahari/internal/domain"
)

const (
	EntityRotation      = "entity_rotation"
	TemporalDilation    = "temporal_dilation"
	SupernodeLaundering = "supernode_laundering"
	NoiseFlood          = "noise_flood"
)

var Strategies = []string{EntityRotation, TemporalDilation, SupernodeLaundering, NoiseFlood}

func Valid(s string) bool {
	for _, x := range Strategies {
		if x == s {
			return true
		}
	}
	return false
}

// Params are the engine settings the attacker is assumed to know.
type Params struct {
	LinkWindow     time.Duration
	SupernodeRatio float64
	SupernodeMinDF int
	// FloodTarget is the hostname decoys cluster on; the caller picks a
	// criticality-9 asset from the CMDB.
	FloodTarget string
}

type Variant struct {
	Alerts []domain.Alert
	Truth  domain.Truth
}

// Generate applies one strategy at budget beta. The base slices are not
// modified.
func Generate(base []domain.Alert, truth domain.Truth, strategy string, beta float64, seed int64, p Params, variantID string) (Variant, error) {
	if !Valid(strategy) {
		return Variant{}, fmt.Errorf("unknown strategy %q", strategy)
	}
	beta = math.Max(0, math.Min(1, beta))
	alerts := make([]domain.Alert, len(base))
	byID := make(map[string]int, len(base))
	for i, a := range base {
		a.DatasetID = variantID
		a.Entities = cloneEntities(a.Entities)
		alerts[i] = a
		byID[a.ID] = i
	}
	t := cloneTruth(truth, variantID)
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(math.Float64bits(beta))^hashStr(strategy)))
	switch strategy {
	case EntityRotation:
		rotate(alerts, byID, t, beta, rng)
	case TemporalDilation:
		dilate(alerts, byID, t, beta, p.LinkWindow)
	case SupernodeLaundering:
		launder(alerts, byID, t, beta, rng, p)
	case NoiseFlood:
		alerts = flood(alerts, &t, beta, rng, p, variantID)
	}
	sort.SliceStable(alerts, func(i, j int) bool {
		if !alerts[i].TS.Equal(alerts[j].TS) {
			return alerts[i].TS.Before(alerts[j].TS)
		}
		return alerts[i].ID < alerts[j].ID
	})
	return Variant{Alerts: alerts, Truth: t}, nil
}

// rotate: with probability β, each step after the first gets a fresh actor
// account and fresh external source IPs. Hosts stay, because the attacker
// still has to reach the same machines.
func rotate(alerts []domain.Alert, byID map[string]int, t domain.Truth, beta float64, rng *rand.Rand) {
	for _, sc := range t.Scenarios {
		for k := 1; k < len(sc.Steps); k++ {
			if rng.Float64() >= beta {
				continue
			}
			user := fmt.Sprintf("u%06x@corp.local", rng.Uint32()&0xffffff)
			ip := fmt.Sprintf("%d.%d.%d.%d", 100+rng.IntN(90), rng.IntN(256), rng.IntN(256), 1+rng.IntN(254))
			for _, id := range sc.Steps[k] {
				i, ok := byID[id]
				if !ok {
					continue
				}
				e := &alerts[i].Entities
				for j, u := range e.Users {
					if u != "system" {
						e.Users[j] = user
					}
				}
				for j, x := range e.IPs {
					if entity.IsExternal(x) {
						e.IPs[j] = ip
					}
				}
			}
		}
	}
}

// dilate scales inter-step gaps by 1 + β·(3W/ḡ − 1), where ḡ is the median gap,
// so at β=1 the median gap is three link windows.
func dilate(alerts []domain.Alert, byID map[string]int, t domain.Truth, beta float64, w time.Duration) {
	for _, sc := range t.Scenarios {
		if len(sc.Steps) < 2 {
			continue
		}
		first := make([]time.Time, len(sc.Steps))
		last := make([]time.Time, len(sc.Steps))
		for k, step := range sc.Steps {
			for _, id := range step {
				i, ok := byID[id]
				if !ok {
					continue
				}
				ts := alerts[i].TS
				if first[k].IsZero() || ts.Before(first[k]) {
					first[k] = ts
				}
				if ts.After(last[k]) {
					last[k] = ts
				}
			}
		}
		var gaps []time.Duration
		for k := 1; k < len(sc.Steps); k++ {
			gaps = append(gaps, max(first[k].Sub(last[k-1]), time.Minute))
		}
		sorted := append([]time.Duration(nil), gaps...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		median := sorted[len(sorted)/2]
		scale := 1 + beta*(3*float64(w)/float64(median)-1)
		if scale < 1 {
			scale = 1 // a scenario already beyond the window is not compressed
		}
		shift := time.Duration(0)
		for k := 1; k < len(sc.Steps); k++ {
			g := gaps[k-1]
			shift += time.Duration(float64(g)*scale) - g
			for _, id := range sc.Steps[k] {
				if i, ok := byID[id]; ok {
					alerts[i].TS = alerts[i].TS.Add(shift).Truncate(time.Second)
				}
			}
		}
	}
}

// launder: with probability β, a step drops every entity it shares with any
// earlier step, and it and the step before it are routed through a
// stop-listed entity instead (a proxy, the DNS server, a shared service
// account). The chain now links only through a supernode, which the
// first linking pass ignores by design.
func launder(alerts []domain.Alert, byID map[string]int, t domain.Truth, beta float64, rng *rand.Rand, p Params) {
	keys := make([][]string, len(alerts))
	for i := range alerts {
		keys[i] = entity.Keys(alerts[i].Entities)
	}
	idx := entity.Build(keys, p.SupernodeRatio, p.SupernodeMinDF)
	var channels []string
	for _, k := range idx.SortedStoplist() {
		switch entity.Type(k) {
		case "ip", "host", "user":
			channels = append(channels, k)
		}
	}
	if len(channels) == 0 {
		return
	}
	stepKeys := func(step []string) map[string]bool {
		out := map[string]bool{}
		for _, id := range step {
			if i, ok := byID[id]; ok {
				for _, k := range entity.Keys(alerts[i].Entities) {
					if !idx.Stoplist[k] {
						out[k] = true
					}
				}
			}
		}
		return out
	}
	for _, sc := range t.Scenarios {
		// Keys each step had before any mutation: an attacker who launders a
		// hop must also drop every identity that would link it back to any
		// earlier step, or the chain simply re-links one step further on.
		orig := make([]map[string]bool, len(sc.Steps))
		for k, step := range sc.Steps {
			orig[k] = stepKeys(step)
		}
		for k := 1; k < len(sc.Steps); k++ {
			if rng.Float64() >= beta {
				continue
			}
			shared := map[string]bool{}
			for key := range orig[k] {
				for j := 0; j < k; j++ {
					if orig[j][key] {
						shared[key] = true
					}
				}
			}
			ch := channels[rng.IntN(len(channels))]
			for _, id := range sc.Steps[k] {
				if i, ok := byID[id]; ok {
					removeKeys(&alerts[i].Entities, shared)
					addKey(&alerts[i].Entities, ch)
				}
			}
			for _, id := range sc.Steps[k-1] {
				if i, ok := byID[id]; ok {
					addKey(&alerts[i].Entities, ch)
				}
			}
		}
	}
}

var floodRules = []struct {
	id, name, tech, source string
	sev                    domain.Severity
}{
	{"MAIL-PHISH-LINK", "Phishing link clicked", "T1566.002", "email", domain.SevHigh},
	{"EDR-PS-ENCODED", "Encoded PowerShell command", "T1059.001", "edr", domain.SevHigh},
	{"EDR-LSASS-ACCESS", "Process accessed LSASS memory", "T1003.001", "edr", domain.SevCritical},
	{"NET-SMB-LATERAL", "SMB admin share access", "T1021.002", "network", domain.SevHigh},
	{"EDR-ARCHIVE", "Large archive created with compression utility", "T1560.001", "edr", domain.SevHigh},
	{"NET-EXFIL-LARGE", "Large outbound transfer to unknown host", "T1041", "network", domain.SevCritical},
}

// flood injects β·400 decoy alerts shaped as attack chains on a high-value
// asset, to push the real chain down the queue. It attacks the ranking, not
// the correlation.
func flood(alerts []domain.Alert, t *domain.Truth, beta float64, rng *rand.Rand, p Params, variantID string) []domain.Alert {
	n := int(math.Round(beta * 400))
	if n == 0 || len(alerts) == 0 {
		return alerts
	}
	start, end := alerts[0].TS, alerts[len(alerts)-1].TS
	for _, a := range alerts {
		if a.TS.Before(start) {
			start = a.TS
		}
		if a.TS.After(end) {
			end = a.TS
		}
	}
	span := end.Sub(start)
	const perCluster = 24
	clusters := (n + perCluster - 1) / perCluster
	target := p.FloodTarget
	if target == "" {
		target = "fin-db-01"
	}
	made := 0
	for c := 0; c < clusters; c++ {
		actor := fmt.Sprintf("svc-decoy%02d@corp.local", c)
		ext := fmt.Sprintf("%d.%d.%d.%d", 150+rng.IntN(50), rng.IntN(256), rng.IntN(256), 1+rng.IntN(254))
		ws := fmt.Sprintf("ws-d%02d", c)
		t0 := start.Add(time.Duration(rng.Int64N(int64(span))))
		group := fmt.Sprintf("noise:decoy-%d", c)
		for k := 0; k < perCluster && made < n; k++ {
			r := floodRules[min(k*len(floodRules)/perCluster, len(floodRules)-1)]
			ents := domain.Entities{Users: []string{actor}, Hosts: []string{ws, target}, IPs: []string{ext}}
			made++
			id := fmt.Sprintf("ALR-X%06d", made)
			alerts = append(alerts, domain.Alert{
				DatasetID: variantID, ID: id, TS: t0.Add(time.Duration(k*3) * time.Minute).Truncate(time.Second),
				Source: r.source, RuleID: r.id, RuleName: r.name, Severity: r.sev, TechniqueID: r.tech,
				Entities: ents.Normalized(), Raw: []byte(`{"decoy":true}`),
			})
			t.Groups[id] = group
		}
	}
	return alerts
}

func removeKeys(e *domain.Entities, drop map[string]bool) {
	f := func(prefix string, xs []string, norm func(string) string) []string {
		out := xs[:0]
		for _, x := range xs {
			if !drop[prefix+norm(x)] {
				out = append(out, x)
			}
		}
		return out
	}
	e.Users = f("user:", e.Users, entity.NormUser)
	e.Hosts = f("host:", e.Hosts, entity.NormHost)
	e.IPs = f("ip:", e.IPs, entity.NormIP)
	e.Processes = f("process:", e.Processes, entity.NormProcess)
	e.Hashes = f("hash:", e.Hashes, entity.NormHash)
}

func addKey(e *domain.Entities, key string) {
	v := entity.Value(key)
	has := func(xs []string) bool {
		for _, x := range xs {
			if x == v {
				return true
			}
		}
		return false
	}
	switch entity.Type(key) {
	case "user":
		if !has(e.Users) {
			e.Users = append(e.Users, v)
		}
	case "host":
		if !has(e.Hosts) {
			e.Hosts = append(e.Hosts, v)
		}
	case "ip":
		if !has(e.IPs) {
			e.IPs = append(e.IPs, v)
		}
	}
}

func cloneEntities(e domain.Entities) domain.Entities {
	c := func(xs []string) []string { return append([]string{}, xs...) }
	return domain.Entities{Users: c(e.Users), Hosts: c(e.Hosts), IPs: c(e.IPs), Processes: c(e.Processes), Hashes: c(e.Hashes)}
}

func cloneTruth(t domain.Truth, id string) domain.Truth {
	out := domain.Truth{DatasetID: id, Seed: t.Seed, Groups: make(map[string]string, len(t.Groups))}
	for k, v := range t.Groups {
		out.Groups[k] = v
	}
	for _, s := range t.Scenarios {
		c := s
		c.AlertIDs = append([]string(nil), s.AlertIDs...)
		c.Steps = make([][]string, len(s.Steps))
		for i := range s.Steps {
			c.Steps[i] = append([]string(nil), s.Steps[i]...)
		}
		out.Scenarios = append(out.Scenarios, c)
	}
	return out
}

func hashStr(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

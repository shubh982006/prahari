// Package counterfactual computes the minimal changes that would flip an
// incident's priority, from the closed-form score. Nothing is stored; at 50
// alerts the whole set takes well under a millisecond.
package counterfactual

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"prahari/internal/core/attack"
	"prahari/internal/core/compliance"
	"prahari/internal/core/correlate"
	"prahari/internal/core/risk"
	"prahari/internal/domain"
)

type Input struct {
	Incident  domain.Incident
	Alerts    []domain.Alert // members, time order
	Assets    map[string]domain.Asset
	Precision map[string]float64 // rule precision as the run saw it
	Attack    correlate.Techniques
	Weights   domain.Weights
	Bands     domain.Bands
	HasCase   bool
	WhatIf    map[string]int // hostname → criticality, previewed not persisted
}

type Item = map[string]any

type Current struct {
	Risk       float64            `json:"risk"`
	Priority   string             `json:"priority"`
	Factors    map[string]float64 `json:"factors"`
	Thresholds domain.Bands       `json:"thresholds"`
	Override   string             `json:"override,omitempty"`
}

type Set struct {
	IncidentID      string  `json:"incident_id"`
	Current         Current `json:"current"`
	Counterfactuals []Item  `json:"counterfactuals"`
}

var factorNames = map[string]string{"C": "chain completeness", "S": "severity", "A": "asset impact", "Q": "confidence"}

const maxAlertItems = 5

func Compute(in Input) Set {
	assets := map[string]domain.Asset{}
	for k, v := range in.Assets {
		assets[k] = v
	}
	for h, c := range in.WhatIf {
		a, ok := assets[h]
		if !ok {
			a = domain.Asset{Hostname: h, Role: "unknown", DataClasses: []string{}}
		}
		a.Criticality = c
		assets[h] = a
	}
	ctx := risk.Context{
		Assets: assets, Weights: in.Weights, Laundered: in.Incident.LaunderingInferred,
		Precision: func(id string) float64 {
			if p, ok := in.Precision[id]; ok {
				return p
			}
			return 0.5
		},
	}
	members := correlate.Members(in.Alerts, in.Attack)
	base := risk.Evaluate(members, ctx)
	basePri := risk.Priority(base, in.Bands)
	baseBreach := compliance.Trigger(basePri, base.MaxStage, base.Hosts, assets) != nil

	set := Set{IncidentID: in.Incident.ID, Current: Current{
		Risk: base.Risk, Priority: basePri, Thresholds: in.Bands, Override: base.Override,
		Factors: map[string]float64{"C": base.C, "S": base.S, "A": base.A, "Q": base.Q},
	}, Counterfactuals: []Item{}}

	closes := func(pri string, maxStage int, hosts []string, as map[string]domain.Asset) bool {
		return in.HasCase && baseBreach && compliance.Trigger(pri, maxStage, hosts, as) == nil
	}
	withFactor := func(c, s, a, q float64) (float64, string) {
		r := risk.Score(c, s, a, q, in.Weights)
		if base.Override != "" {
			return r, "P1"
		}
		return r, in.Bands.Priority(r)
	}
	add := func(it Item) { set.Counterfactuals = append(set.Counterfactuals, it) }

	// asset: remove the sensitive tags, then treat as an ordinary workstation
	for _, ta := range base.TopAssets {
		a := assets[ta.Hostname]
		if a.Sensitive() {
			mod := clone(assets)
			na := a
			na.DataClasses = without(a.DataClasses, "pii", "financial")
			mod[a.Hostname] = na
			add(assetItem(fmt.Sprintf("if %s were not tagged %s", a.Hostname, strings.Join(only(a.DataClasses, "pii", "financial"), " or ")),
				members, ctx, mod, in, base, closes))
		}
		if a.Criticality > 3 {
			mod := clone(assets)
			na := a
			na.Criticality = 3
			na.DataClasses = []string{}
			mod[a.Hostname] = na
			add(assetItem(fmt.Sprintf("if %s were an ordinary workstation (criticality 3)", a.Hostname), members, ctx, mod, in, base, closes))
		}
	}

	// factor: truncate the forward path to a length that actually lowers C
	// (C saturates at four stages, so dropping one stage from six changes
	// nothing and would be a useless counterfactual)
	if base.ForwardStages >= 2 {
		keep := min(base.ForwardStages-1, 3)
		c := risk.Round2(risk.ChainFactor(keep))
		last := members[base.Chain[keep-1]]
		r, p := withFactor(c, base.S, base.A, base.Q)
		stopAt := strings.ToLower(last.Tactic)
		if stopAt == "" {
			stopAt = strings.ToLower(attack.StageNames[max(last.Stage, 0)])
		}
		add(Item{"kind": "factor", "factor": "C", "label": "if the chain had stopped at " + stopAt, "value": c,
			"risk": r, "priority": p, "delta": risk.Round2(r - base.Risk),
			"closes_case": closes(p, last.Stage, hostsUpTo(members, base.Chain[keep-1]), assets)})
	}
	if base.MaxSeverity.Score() > domain.SevMedium.Score() {
		s := risk.Round2(0.5*domain.SevMedium.Score() + 0.5*float64(base.MaxStage)/6)
		r, p := withFactor(base.C, s, base.A, base.Q)
		add(Item{"kind": "factor", "factor": "S", "label": "if the worst alert were only medium severity", "value": s,
			"risk": r, "priority": p, "delta": risk.Round2(r - base.Risk), "closes_case": closes(p, base.MaxStage, base.Hosts, assets)})
	}
	if base.Q > 0.30 {
		r, p := withFactor(base.C, base.S, base.A, 0.30)
		add(Item{"kind": "factor", "factor": "Q", "label": "if confidence dropped to 0.30", "value": 0.30,
			"risk": r, "priority": p, "delta": risk.Round2(r - base.Risk), "closes_case": closes(p, base.MaxStage, base.Hosts, assets)})
	}

	// alert removal: recompute everything without one alert
	var alertItems []Item
	candidates := map[int]bool{}
	for _, c := range base.Chain {
		candidates[c] = true
	}
	for i, m := range members {
		if m.Severity == domain.SevCritical {
			candidates[i] = true
		}
	}
	idx := make([]int, 0, len(candidates))
	for i := range candidates {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	if len(members) > 1 {
		for _, i := range idx {
			rest := append(append([]risk.Member{}, members[:i]...), members[i+1:]...)
			res := risk.Evaluate(rest, ctx)
			p := risk.Priority(res, in.Bands)
			cl := closes(p, res.MaxStage, res.Hosts, assets)
			delta := risk.Round2(res.Risk - base.Risk)
			if p == basePri && !cl && math.Abs(delta) < 5 {
				continue
			}
			alertItems = append(alertItems, Item{"kind": "alert", "alert_id": members[i].ID, "label": "remove " + members[i].ID,
				"risk": res.Risk, "priority": p, "delta": delta, "closes_case": cl})
		}
	}
	sort.SliceStable(alertItems, func(i, j int) bool {
		ci, cj := alertItems[i]["closes_case"].(bool), alertItems[j]["closes_case"].(bool)
		if ci != cj {
			return ci
		}
		return alertItems[i]["delta"].(float64) < alertItems[j]["delta"].(float64)
	})
	if len(alertItems) > maxAlertItems {
		alertItems = alertItems[:maxAlertItems]
	}
	set.Counterfactuals = append(set.Counterfactuals, alertItems...)

	// Drop items that change nothing an analyst acts on.
	kept := set.Counterfactuals[:0]
	for _, it := range set.Counterfactuals {
		if it["priority"] == basePri && it["closes_case"] == false && it["delta"] == 0.0 {
			continue
		}
		kept = append(kept, it)
	}
	set.Counterfactuals = kept

	// boundary: solve each factor for the band edge
	target, below, bandName := boundaryTarget(basePri, in.Bands)
	for _, f := range []string{"C", "S", "A", "Q"} {
		name := factorNames[f]
		if base.Override != "" && below {
			add(Item{"kind": "boundary", "factor": f, "target_value": nil, "reachable": false,
				"label": fmt.Sprintf("the P1 floor holds regardless of %s (%s)", name, strings.TrimPrefix(base.Override, "P1 floor: "))})
			continue
		}
		v, ok := risk.SolveFactor(f, target, base.C, base.S, base.A, base.Q, in.Weights)
		if !ok {
			verb := "below " + bandName
			if !below {
				verb = "up to " + bandName
			}
			add(Item{"kind": "boundary", "factor": f, "target_value": nil, "reachable": false,
				"label": fmt.Sprintf("%s alone cannot move this %s", sentenceCase(name), verb)})
			continue
		}
		// Round away from the edge so the stated value actually crosses it.
		var tv float64
		var label string
		if below {
			tv = math.Floor(v*100-1e-9) / 100
			label = fmt.Sprintf("to fall below %s, %s would need to be ≤ %.2f", bandName, name, tv)
		} else {
			tv = math.Ceil(v*100+1e-9) / 100
			label = fmt.Sprintf("to reach %s, %s would need to be ≥ %.2f", bandName, name, tv)
		}
		add(Item{"kind": "boundary", "factor": f, "target_value": tv, "reachable": true, "label": label})
	}
	return set
}

func assetItem(label string, members []risk.Member, ctx risk.Context, mod map[string]domain.Asset, in Input, base risk.Result,
	closes func(string, int, []string, map[string]domain.Asset) bool) Item {
	c := ctx
	c.Assets = mod
	res := risk.Evaluate(members, c)
	p := risk.Priority(res, in.Bands)
	return Item{"kind": "asset", "label": label, "risk": res.Risk, "priority": p,
		"delta": risk.Round2(res.Risk - base.Risk), "closes_case": closes(p, res.MaxStage, res.Hosts, mod)}
}

// boundaryTarget returns the score edge to solve for: the lower edge of the
// current band, or for P4 the P3 edge above.
func boundaryTarget(pri string, b domain.Bands) (float64, bool, string) {
	switch pri {
	case "P1":
		return b.P1, true, "P1"
	case "P2":
		return b.P2, true, "P2"
	case "P3":
		return b.P3, true, "P3"
	}
	return b.P3, false, "P3"
}

func hostsUpTo(ms []risk.Member, last int) []string {
	seen := map[string]bool{}
	var out []string
	for i := 0; i <= last && i < len(ms); i++ {
		for _, h := range ms[i].Hosts {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sort.Strings(out)
	return out
}

func clone(m map[string]domain.Asset) map[string]domain.Asset {
	out := make(map[string]domain.Asset, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func without(xs []string, drop ...string) []string {
	out := []string{}
	for _, x := range xs {
		keep := true
		for _, d := range drop {
			if x == d {
				keep = false
			}
		}
		if keep {
			out = append(out, x)
		}
	}
	return out
}

func only(xs []string, keep ...string) []string {
	var out []string
	for _, x := range xs {
		for _, k := range keep {
			if x == k {
				out = append(out, x)
			}
		}
	}
	return out
}

func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Package risk scores an incident from its member alerts.
//
//	risk = 100 · C^wC · S^wS · A^wA · Q^wQ
//
// Geometric, not a weighted sum: a sum lets one strong factor hide a zero.
// Factors are rounded to two decimals before scoring so that the breakdown the
// analyst sees reproduces the score exactly by hand.
package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"prahari/internal/domain"
)

var DefaultWeights = domain.Weights{C: 0.35, S: 0.20, A: 0.30, Q: 0.15}

// FixedBands are the legacy thresholds, kept for band_mode=fixed.
var FixedBands = domain.Bands{P1: 80, P2: 55, P3: 35}

const (
	UnknownHostImpact = 0.3
	SensitiveUplift   = 0.2
	LaunderingPenalty = 0.85
	OverrideMinCrit   = 7
)

// Member is the slice of an alert that scoring needs.
type Member struct {
	ID       string
	TS       time.Time
	Severity domain.Severity
	Stage    int    // -1 when the technique is unknown
	Tactic   string // tactic that decided the stage
	RuleID   string
	Hosts    []string // normalised
}

type Context struct {
	Assets    map[string]domain.Asset
	Precision func(ruleID string) float64
	Weights   domain.Weights
	Laundered bool
}

type Result struct {
	C, S, A, Q    float64
	Risk          float64
	ForwardStages int
	Chain         []int // indices into the (time-ordered) members on the forward path
	MaxStage      int
	MaxSeverity   domain.Severity
	Override      string // non-empty when the P1 floor applies
	TopAssets     []domain.BreakdownAsset
	Rules         []domain.BreakdownRule
	Hosts         []string // sorted
}

// Evaluate computes the four factors and the unbanded score. Members must be
// in time order.
func Evaluate(ms []Member, ctx Context) Result {
	var r Result
	stages := make([]int, 0, len(ms))
	stageIdx := make([]int, 0, len(ms))
	for i, m := range ms {
		if m.Stage >= 0 {
			stages = append(stages, m.Stage)
			stageIdx = append(stageIdx, i)
			r.MaxStage = max(r.MaxStage, m.Stage)
		}
		if m.Severity.Score() > r.MaxSeverity.Score() {
			r.MaxSeverity = m.Severity
		}
	}
	n, path := ForwardPath(stages)
	r.ForwardStages = n
	for _, p := range path {
		r.Chain = append(r.Chain, stageIdx[p])
	}

	r.C = Round2(ChainFactor(n))
	r.S = Round2(0.5*r.MaxSeverity.Score() + 0.5*float64(r.MaxStage)/6)
	r.A, r.TopAssets, r.Hosts = AssetFactor(ms, ctx.Assets)
	r.A = Round2(r.A)
	r.Rules = rules(ms, ctx.Precision)
	q := 1.0
	for _, rl := range r.Rules {
		q *= 1 - rl.Precision
	}
	r.Q = 1 - q
	if ctx.Laundered {
		r.Q *= LaunderingPenalty
	}
	r.Q = Round2(r.Q)
	r.Risk = Score(r.C, r.S, r.A, r.Q, ctx.Weights)
	r.Override = override(ms, ctx.Assets)
	return r
}

// ChainFactor is C for a forward path of length lis.
func ChainFactor(lis int) float64 {
	if lis <= 0 {
		return 0.2
	}
	return 0.2 + 0.8*math.Min(1, float64(lis-1)/3)
}

// Score is the closed form. Explicit float64 conversions stop the compiler
// fusing multiply-adds, which would make results differ across CPUs.
func Score(c, s, a, q float64, w domain.Weights) float64 {
	v := float64(math.Pow(c, w.C)) * float64(math.Pow(s, w.S))
	v = float64(v*float64(math.Pow(a, w.A))) * float64(math.Pow(q, w.Q))
	return Round2(100 * v)
}

// AssetFactor is A: the highest criticality/10 among touched hosts, an unknown
// host counting 0.3, plus 0.2 (capped at 1) when any known asset holds pii or
// financial data.
func AssetFactor(ms []Member, assets map[string]domain.Asset) (float64, []domain.BreakdownAsset, []string) {
	seen := map[string]bool{}
	var hosts []string
	for _, m := range ms {
		for _, h := range m.Hosts {
			if h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	sort.Strings(hosts)
	if len(hosts) == 0 {
		return UnknownHostImpact, nil, hosts
	}
	a := 0.0
	sensitive := false
	var known []domain.BreakdownAsset
	for _, h := range hosts {
		as, ok := assets[h]
		if !ok {
			a = math.Max(a, UnknownHostImpact)
			continue
		}
		a = math.Max(a, float64(as.Criticality)/10)
		if as.Sensitive() {
			sensitive = true
		}
		dc := as.DataClasses
		if dc == nil {
			dc = []string{}
		}
		known = append(known, domain.BreakdownAsset{Hostname: h, Criticality: as.Criticality, DataClasses: dc, Known: true})
	}
	if sensitive {
		a = math.Min(1, a+SensitiveUplift)
	}
	sort.SliceStable(known, func(i, j int) bool {
		if known[i].Criticality != known[j].Criticality {
			return known[i].Criticality > known[j].Criticality
		}
		return known[i].Hostname < known[j].Hostname
	})
	if len(known) > 3 {
		known = known[:3]
	}
	return a, known, hosts
}

func rules(ms []Member, precision func(string) float64) []domain.BreakdownRule {
	count := map[string]int{}
	for _, m := range ms {
		count[m.RuleID]++
	}
	out := make([]domain.BreakdownRule, 0, len(count))
	for id, n := range count {
		p := 0.5
		if precision != nil {
			p = precision(id)
		}
		out = append(out, domain.BreakdownRule{RuleID: id, Precision: Round2(p), Alerts: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alerts != out[j].Alerts {
			return out[i].Alerts > out[j].Alerts
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// override is the hard floor: a critical alert at stage 6 on an asset with
// criticality >= 7 is P1 regardless of bands.
func override(ms []Member, assets map[string]domain.Asset) string {
	best := ""
	bestCrit := 0
	tactic := ""
	for _, m := range ms {
		if m.Severity != domain.SevCritical || m.Stage != 6 {
			continue
		}
		for _, h := range m.Hosts {
			if a, ok := assets[h]; ok && a.Criticality >= OverrideMinCrit {
				if a.Criticality > bestCrit || (a.Criticality == bestCrit && h < best) {
					best, bestCrit, tactic = h, a.Criticality, m.Tactic
				}
			}
		}
	}
	if best == "" {
		return ""
	}
	if tactic == "" {
		tactic = "stage-6 activity"
	}
	return fmt.Sprintf("P1 floor: critical %s on %s (criticality %d)", strings.ToLower(tactic), best, bestCrit)
}

// Priority applies bands and the override.
func Priority(r Result, b domain.Bands) string {
	if r.Override != "" {
		return "P1"
	}
	return b.Priority(r.Risk)
}

// Capacity sizes the calibrated bands to what one shift can work.
type Capacity struct {
	P1PerShift int `json:"p1_per_shift"`
	P2PerShift int `json:"p2_per_shift"`
}

var DefaultCapacity = Capacity{P1PerShift: 5, P2PerShift: 10}

// Calibrate derives thresholds from this run's score distribution: the P1 edge
// is the score of the Nth incident where N is P1 capacity, the P2 edge covers
// the next P2-capacity incidents, and P3 is the 40th percentile. Clamps keep a
// tiny dataset from producing absurd cutoffs.
func Calibrate(scores []float64, c Capacity) domain.Bands {
	s := append([]float64(nil), scores...)
	sort.Sort(sort.Reverse(sort.Float64Slice(s)))
	n := len(s)
	at := func(k int) float64 {
		if n == 0 {
			return 0
		}
		return s[min(max(k, 0), n-1)]
	}
	p1 := clamp(at(c.P1PerShift-1), 60, 95)
	p2 := clamp(at(c.P1PerShift+c.P2PerShift-1), 40, p1)
	p3 := clamp(at(int(float64(n)*0.40)), 20, p2)
	return domain.Bands{P1: Round2(p1), P2: Round2(p2), P3: Round2(p3)}
}

func clamp(v, lo, hi float64) float64 { return math.Min(math.Max(v, lo), hi) }

// ForwardPath returns the longest strictly increasing subsequence of stages
// and the indices of one such subsequence. Reconstruction is deterministic for
// a given input order, so the anchor (first index) is stable across runs.
func ForwardPath(stages []int) (int, []int) {
	if len(stages) == 0 {
		return 0, nil
	}
	tails := make([]int, 0, 7) // index into stages of the smallest tail for each length
	prev := make([]int, len(stages))
	for i, s := range stages {
		lo, hi := 0, len(tails)
		for lo < hi { // first tail >= s → strictly increasing
			mid := (lo + hi) / 2
			if stages[tails[mid]] < s {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			prev[i] = tails[lo-1]
		} else {
			prev[i] = -1
		}
		if lo == len(tails) {
			tails = append(tails, i)
		} else {
			tails[lo] = i
		}
	}
	n := len(tails)
	path := make([]int, n)
	for k, i := n-1, tails[n-1]; k >= 0; k-- {
		path[k] = i
		i = prev[i]
	}
	return n, path
}

// SolveFactor returns the value factor f would need for the score to equal
// target with the other factors fixed, and whether it lies in [lo,1].
func SolveFactor(f string, target float64, c, s, a, q float64, w domain.Weights) (float64, bool) {
	var rest, exp, lo float64
	switch f {
	case "C":
		rest = math.Pow(s, w.S) * math.Pow(a, w.A) * math.Pow(q, w.Q)
		exp, lo = w.C, 0.2
	case "S":
		rest = math.Pow(c, w.C) * math.Pow(a, w.A) * math.Pow(q, w.Q)
		exp = w.S
	case "A":
		rest = math.Pow(c, w.C) * math.Pow(s, w.S) * math.Pow(q, w.Q)
		exp = w.A
	case "Q":
		rest = math.Pow(c, w.C) * math.Pow(s, w.S) * math.Pow(a, w.A)
		exp = w.Q
	default:
		return 0, false
	}
	if rest == 0 || exp == 0 {
		return 0, false
	}
	v := math.Pow(target/(100*rest), 1/exp)
	if math.IsNaN(v) || v < lo || v > 1 {
		return v, false
	}
	return v, true
}

func Round2(v float64) float64 { return math.Round(v*100) / 100 }

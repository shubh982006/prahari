package evade

import (
	"sort"

	"prahari/internal/core/evaluate"
	"prahari/internal/domain"
)

// Point is one budget on the evasion curve.
type Point struct {
	Budget             float64 `json:"budget"`
	ScenarioRecall     float64 `json:"scenario_recall"`
	PairwisePrecision  float64 `json:"pairwise_precision"`
	PairwiseRecall     float64 `json:"pairwise_recall"`
	Incidents          int     `json:"incidents"`
	Detected           bool    `json:"detected"`
	TopRank            *int    `json:"top_rank"`
	ScenariosEvaluated int     `json:"scenarios_evaluated"`
}

// Baseline returns the scenarios detected in an unmutated run. The curve's
// recall is measured over these only: E and F are deliberate misses at any
// budget, and counting them would put every curve below the floor at β=0 and
// hide the degradation the bench exists to show.
func Baseline(incidents []domain.Incident, t domain.Truth, alertOrder []string) map[string]bool {
	_, sc := evaluate.Evaluate(incidents, t, alertOrder, evaluate.DefaultAnalyst)
	out := map[string]bool{}
	for _, s := range sc {
		if s.Detected {
			out[s.Scenario] = true
		}
	}
	return out
}

// Flagship is the scenario whose rank the curve reports: A when present,
// otherwise the first detected scenario.
func Flagship(consider map[string]bool) string {
	if consider["A"] {
		return "A"
	}
	var ks []string
	for k := range consider {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	if len(ks) == 0 {
		return ""
	}
	return ks[0]
}

func Score(budget float64, incidents []domain.Incident, t domain.Truth, consider map[string]bool, alertOrder []string) Point {
	m, sc := evaluate.Evaluate(incidents, t, alertOrder, evaluate.DefaultAnalyst)
	p := Point{Budget: budget, PairwisePrecision: m.PairwisePrecision, PairwiseRecall: m.PairwiseRecall,
		Incidents: len(incidents), ScenariosEvaluated: len(consider)}
	flag := Flagship(consider)
	hit := 0
	for _, s := range sc {
		if !consider[s.Scenario] {
			continue
		}
		if s.Detected {
			hit++
		}
		if s.Scenario == flag && s.Detected {
			p.Detected = true
			r := *s.Rank
			p.TopRank = &r
		}
	}
	if len(consider) > 0 {
		p.ScenarioRecall = float64(int(float64(hit)/float64(len(consider))*100+0.5)) / 100
	}
	return p
}

// CrossesFloor returns the interpolated budget where a series first drops
// below floor, or nil when it never does within the tested range.
func CrossesFloor(budgets, values []float64, floor float64) *float64 {
	for i := range values {
		if values[i] >= floor {
			continue
		}
		if i == 0 {
			b := budgets[0]
			return &b
		}
		b0, b1, v0, v1 := budgets[i-1], budgets[i], values[i-1], values[i]
		x := b0
		if v0 != v1 {
			x = b0 + (floor-v0)*(b1-b0)/(v1-v0)
		}
		x = float64(int(x*1000+0.5)) / 1000
		return &x
	}
	return nil
}

// Package evaluate scores a run's incidents against hidden ground truth.
//
// Definitions, stated once so every number can be defended:
//
//   - A scenario is detected when one incident holds at least 70% of its
//     alerts. Coverage is the largest such fraction.
//   - Pairwise precision and recall are computed over alert pairs where at
//     least one alert belongs to a scenario. Noise-noise pairs are excluded,
//     otherwise a single large noise cluster dominates both numbers.
//   - An incident is "true" when its dominant truth group is a scenario, or it
//     is the incident that detects a scenario.
//   - The baseline analyst reads alerts in timestamp order; the Prahari
//     analyst reads incidents in rank order.
package evaluate

import (
	"sort"
	"strconv"

	"prahari/internal/domain"
)

const DetectionThreshold = 0.70

type AnalystModel struct {
	SecondsPerAlert    int `json:"seconds_per_alert"`
	SecondsPerIncident int `json:"seconds_per_incident"`
}

var DefaultAnalyst = AnalystModel{SecondsPerAlert: 30, SecondsPerIncident: 180}

type Metrics struct {
	CompressionRatio           float64 `json:"compression_ratio"`
	ScenarioRecall             float64 `json:"scenario_recall"`
	PairwisePrecision          float64 `json:"pairwise_precision"`
	PairwiseRecall             float64 `json:"pairwise_recall"`
	MeanPurity                 float64 `json:"mean_purity"`
	PrecisionAt5               float64 `json:"precision_at_5"`
	CohesionAccuracy           float64 `json:"cohesion_accuracy"`
	FragileIncidents           int     `json:"fragile_incidents"`
	TimeToFirstAttackBaselineS int     `json:"time_to_first_attack_baseline_s"`
	TimeToFirstAttackPrahariS  int     `json:"time_to_first_attack_prahari_s"`
	TriageTimeReduction        float64 `json:"triage_time_reduction"`
	NoiseInTop10               float64 `json:"noise_in_top10"`
	CorrelateMS                int64   `json:"correlate_ms"`
}

type Scenario struct {
	Scenario         string  `json:"scenario"`
	Name             string  `json:"name"`
	Detected         bool    `json:"detected"`
	Coverage         float64 `json:"coverage"`
	IncidentID       *string `json:"incident_id"`
	Rank             *int    `json:"rank"`
	ExpectedPriority string  `json:"expected_priority"`
	ActualPriority   *string `json:"actual_priority"`
	MissReason       *string `json:"miss_reason"`
}

// Baseline states the comparison in words, because a reduction without its
// baseline is not evidence.
func Baseline(m AnalystModel) string {
	return "analyst reads alerts in timestamp order at " + itoa(m.SecondsPerAlert) +
		" s per alert; Prahari analyst reads incidents in rank order at " + itoa(m.SecondsPerIncident) + " s per incident"
}

// Evaluate computes metrics. incidents must be in rank order; alertOrder is
// every alert ID in timestamp order (the baseline analyst's reading order).
func Evaluate(incidents []domain.Incident, truth domain.Truth, alertOrder []string, model AnalystModel) (Metrics, []Scenario) {
	var m Metrics
	if model.SecondsPerAlert == 0 {
		model = DefaultAnalyst
	}
	if len(incidents) > 0 {
		m.CompressionRatio = round2(float64(len(alertOrder)) / float64(len(incidents)))
	}
	group := func(id string) string {
		if g, ok := truth.Groups[id]; ok {
			return g
		}
		return "noise:unknown"
	}
	incOf := map[string]int{}
	for i, inc := range incidents {
		for _, a := range inc.AlertIDs {
			incOf[a] = i
		}
	}

	// scenarios
	detectedBy := map[int]bool{}
	var out []Scenario
	for _, sc := range truth.Scenarios {
		r := Scenario{Scenario: sc.Scenario, Name: sc.Name, ExpectedPriority: sc.ExpectedPriority}
		count := map[int]int{}
		for _, a := range sc.AlertIDs {
			if i, ok := incOf[a]; ok {
				count[i]++
			}
		}
		best, bestN := -1, 0
		for i, n := range count {
			if n > bestN || (n == bestN && i < best) {
				best, bestN = i, n
			}
		}
		if len(sc.AlertIDs) > 0 {
			r.Coverage = round2(float64(bestN) / float64(len(sc.AlertIDs)))
		}
		if best >= 0 {
			id, rank, pr := incidents[best].ID, incidents[best].Rank, incidents[best].Priority
			r.IncidentID, r.Rank, r.ActualPriority = &id, &rank, &pr
		}
		r.Detected = r.Coverage >= DetectionThreshold
		if r.Detected {
			detectedBy[best] = true
		} else {
			reason := sc.DeliberateMiss
			if reason == "" {
				reason = "alerts split across incidents; best incident holds " + pct(r.Coverage)
			}
			r.MissReason = &reason
		}
		out = append(out, r)
	}
	nDetected := 0
	for _, s := range out {
		if s.Detected {
			nDetected++
		}
	}
	if len(out) > 0 {
		m.ScenarioRecall = round2(float64(nDetected) / float64(len(out)))
	}

	// pairwise, purity, truth of incidents
	scenSize := map[string]int{}
	for _, inc := range incidents {
		for _, a := range inc.AlertIDs {
			if g := group(a); domain.IsScenarioGroup(g) {
				scenSize[g]++
			}
		}
	}
	var truePairs, predPairs, tp float64
	for _, n := range scenSize {
		truePairs += pairs(n)
	}
	isTrue := make([]bool, len(incidents))
	var puritySum float64
	purityN := 0
	for i, inc := range incidents {
		counts := map[string]int{}
		k := 0
		for _, a := range inc.AlertIDs {
			g := group(a)
			counts[g]++
			if domain.IsScenarioGroup(g) {
				k++
			}
		}
		size := len(inc.AlertIDs)
		predPairs += pairs(size) - pairs(size-k)
		dom, domN := "", 0
		keys := make([]string, 0, len(counts))
		for g := range counts {
			keys = append(keys, g)
		}
		sort.Strings(keys)
		for _, g := range keys {
			if domain.IsScenarioGroup(g) {
				tp += pairs(counts[g])
			}
			if counts[g] > domN {
				dom, domN = g, counts[g]
			}
		}
		if k > 0 {
			puritySum += float64(domN) / float64(size)
			purityN++
		}
		isTrue[i] = domain.IsScenarioGroup(dom) || detectedBy[i]
	}
	if predPairs > 0 {
		m.PairwisePrecision = round2(tp / predPairs)
	}
	if truePairs > 0 {
		m.PairwiseRecall = round2(tp / truePairs)
	}
	if purityN > 0 {
		m.MeanPurity = round2(puritySum / float64(purityN))
	}
	topTrue := func(k int) float64 {
		n := min(k, len(incidents))
		if n == 0 {
			return 0
		}
		c := 0
		for i := 0; i < n; i++ {
			if isTrue[i] {
				c++
			}
		}
		return float64(c) / float64(n)
	}
	m.PrecisionAt5 = round2(topTrue(5))
	if len(incidents) > 0 {
		m.NoiseInTop10 = round2(1 - topTrue(10))
	}

	// cohesion accuracy: a fragile flag is right when the two halves of the
	// proposed split belong to different truth groups.
	right := 0
	for _, inc := range incidents {
		if inc.Cohesion != "fragile" || inc.SplitPreview == nil {
			continue
		}
		m.FragileIncidents++
		if dominant(inc.SplitPreview.Left.AlertIDs, group) != dominant(inc.SplitPreview.Right.AlertIDs, group) {
			right++
		}
	}
	if m.FragileIncidents > 0 {
		m.CohesionAccuracy = round2(float64(right) / float64(m.FragileIncidents))
	}

	// time to first attack
	for i, a := range alertOrder {
		if domain.IsScenarioGroup(group(a)) {
			m.TimeToFirstAttackBaselineS = (i + 1) * model.SecondsPerAlert
			break
		}
	}
	for i := range incidents {
		if isTrue[i] {
			m.TimeToFirstAttackPrahariS = (i + 1) * model.SecondsPerIncident
			break
		}
	}
	if m.TimeToFirstAttackBaselineS > 0 && m.TimeToFirstAttackPrahariS > 0 {
		m.TriageTimeReduction = round2(1 - float64(m.TimeToFirstAttackPrahariS)/float64(m.TimeToFirstAttackBaselineS))
	}
	return m, out
}

func dominant(ids []string, group func(string) string) string {
	c := map[string]int{}
	for _, a := range ids {
		c[group(a)]++
	}
	best, n := "", 0
	keys := make([]string, 0, len(c))
	for g := range c {
		keys = append(keys, g)
	}
	sort.Strings(keys)
	for _, g := range keys {
		if c[g] > n {
			best, n = g, c[g]
		}
	}
	return best
}

func pairs(n int) float64 { return float64(n) * float64(n-1) / 2 }

func round2(v float64) float64 {
	if v < 0 {
		return -round2(-v)
	}
	return float64(int64(v*100+0.5)) / 100
}

func pct(v float64) string { return itoa(int(v*100+0.5)) + "%" }

func itoa(n int) string { return strconv.Itoa(n) }

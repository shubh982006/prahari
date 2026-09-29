package evade_test

import (
	"testing"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/evade"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

// The laundering pass (design §6.4) exists to close the hole the stop-list
// opens. Across the bench's budgets and seeds, the mitigated series must never
// fall below the unmitigated one on supernode_laundering, and must beat it
// somewhere — otherwise the mitigation overlay on the curve is decoration.
// This checks the shape, not the numbers: those come from running the bench.
func TestLaunderingPassBeatsSupernodeLaundering(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine 60 times")
	}
	cat, err := attack.LoadFile("../../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string]domain.Asset{}
	for _, a := range simulate.CMDB() {
		assets[a.Hostname] = a
	}
	stats := map[string]domain.RuleStat{}
	for _, r := range simulate.AllRuleStats() {
		stats[r.RuleID] = r
	}
	run := func(id string, alerts []domain.Alert, mitigated bool) []domain.Incident {
		cfg := correlate.DefaultConfig()
		cfg.LaunderingPass = mitigated
		out, err := correlate.Run(correlate.Input{DatasetID: id, Alerts: alerts, Assets: assets, RuleStats: stats, Attack: cat,
			Config: cfg, RunStarted: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}, correlate.Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		return out.Incidents
	}
	order := func(as []domain.Alert) []string {
		o := make([]string, len(as))
		for i, a := range as {
			o[i] = a.ID
		}
		return o
	}
	cfg := correlate.DefaultConfig()
	params := evade.Params{LinkWindow: cfg.LinkWindow, SupernodeRatio: cfg.SupernodeRatio, SupernodeMinDF: cfg.SupernodeMinDF, FloodTarget: "pay-db-01"}
	budgets := []float64{0, 0.25, 0.5, 0.75, 1}
	seeds := []int64{1, 2, 3, 4, 5}

	curve := func(mitigated bool) []float64 {
		sum := make([]float64, len(budgets))
		for _, seed := range seeds {
			sim := simulate.Generate(simulate.Params{Seed: seed})
			base := sim.All()
			consider := evade.Baseline(run(sim.DatasetID, base, mitigated), sim.Truth, order(base))
			for i, b := range budgets {
				v, err := evade.Generate(base, sim.Truth, evade.SupernodeLaundering, b, seed, params, "ds_adv")
				if err != nil {
					t.Fatal(err)
				}
				sum[i] += evade.Score(b, run("ds_adv", v.Alerts, mitigated), v.Truth, consider, order(v.Alerts)).ScenarioRecall
			}
		}
		for i := range sum {
			sum[i] /= float64(len(seeds))
		}
		return sum
	}
	off, on := curve(false), curve(true)
	t.Logf("budgets     %v", budgets)
	t.Logf("unmitigated %v", off)
	t.Logf("mitigated   %v", on)

	better := false
	for i := range budgets {
		if on[i] < off[i]-1e-9 {
			t.Errorf("β=%.2f: mitigated recall %.2f below unmitigated %.2f", budgets[i], on[i], off[i])
		}
		if on[i] > off[i]+1e-9 {
			better = true
		}
	}
	if !better {
		t.Error("the laundering pass recovers nothing at any budget")
	}
	if off[len(off)-1] >= off[0] {
		t.Errorf("unmitigated recall should degrade with budget: %v", off)
	}
}

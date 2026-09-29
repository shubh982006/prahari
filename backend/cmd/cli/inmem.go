package main

import (
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/evaluate"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

// inmemRun simulates a dataset and correlates it without any database: the
// same pure path the API takes after loading from storage.
type inmemRun struct {
	sim     simulate.Result
	alerts  []domain.Alert
	out     correlate.Output
	elapsed time.Duration
	metrics evaluate.Metrics
	scen    []evaluate.Scenario
}

func baseInput(cat *attack.Catalog, datasetID string, alerts []domain.Alert, cfg correlate.Config) correlate.Input {
	assets := map[string]domain.Asset{}
	for _, a := range simulate.CMDB() {
		assets[a.Hostname] = a
	}
	stats := map[string]domain.RuleStat{}
	for _, r := range simulate.AllRuleStats() {
		stats[r.RuleID] = r
	}
	return correlate.Input{
		DatasetID: datasetID, Alerts: alerts, Assets: assets, RuleStats: stats,
		Attack: cat, Config: cfg, RunStarted: simulate.DefaultStart.Add(36 * time.Hour),
	}
}

func runInMemory(cat *attack.Catalog, p simulate.Params, cfg correlate.Config) (inmemRun, error) {
	var r inmemRun
	r.sim = simulate.Generate(p)
	r.alerts = r.sim.All()
	start := time.Now()
	out, err := correlate.Run(baseInput(cat, r.sim.DatasetID, r.alerts, cfg), correlate.Hooks{})
	if err != nil {
		return r, err
	}
	r.elapsed = time.Since(start)
	r.out = out
	order := make([]string, len(r.alerts))
	for i, a := range r.alerts {
		order[i] = a.ID
	}
	r.metrics, r.scen = evaluate.Evaluate(out.Incidents, r.sim.Truth, order, evaluate.DefaultAnalyst)
	r.metrics.CorrelateMS = r.elapsed.Milliseconds()
	return r, nil
}

package counterfactual

import (
	"testing"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/risk"
	"prahari/internal/domain"
)

func TestBoundaryLandsOnTheBandEdge(t *testing.T) {
	cat, err := attack.LoadFile("../../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 9, 29, 4, 0, 0, 0, time.UTC)
	alerts := []domain.Alert{
		{ID: "a1", TS: t0, Severity: domain.SevHigh, TechniqueID: "T1566.001", RuleID: "R1", Entities: domain.Entities{Hosts: []string{"ws-1"}}},
		{ID: "a2", TS: t0.Add(time.Minute), Severity: domain.SevHigh, TechniqueID: "T1059.001", RuleID: "R2", Entities: domain.Entities{Hosts: []string{"ws-1"}}},
		{ID: "a3", TS: t0.Add(2 * time.Minute), Severity: domain.SevHigh, TechniqueID: "T1021.001", RuleID: "R3", Entities: domain.Entities{Hosts: []string{"ws-1", "srv"}}},
	}
	assets := map[string]domain.Asset{"srv": {Hostname: "srv", Criticality: 8}, "ws-1": {Hostname: "ws-1", Criticality: 3}}
	bands := domain.Bands{P1: 70, P2: 50, P3: 30}
	set := Compute(Input{Incident: domain.Incident{ID: "INC-1"}, Alerts: alerts, Assets: assets,
		Precision: map[string]float64{"R1": 0.5, "R2": 0.5, "R3": 0.5}, Attack: cat, Weights: risk.DefaultWeights, Bands: bands})
	if set.Current.Priority != "P1" {
		t.Fatalf("setup: %+v", set.Current)
	}
	f := set.Current.Factors
	found := false
	for _, c := range set.Counterfactuals {
		if c["kind"] != "boundary" || c["factor"] != "A" {
			continue
		}
		found = true
		v := c["target_value"].(float64)
		if got := risk.Score(f["C"], f["S"], v, f["Q"], risk.DefaultWeights); got >= bands.P1 {
			t.Fatalf("A=%.2f still scores %.2f ≥ P1 edge %.2f", v, got, bands.P1)
		}
	}
	if !found {
		t.Fatal("no boundary for A")
	}
	what := Compute(Input{Incident: domain.Incident{ID: "INC-1"}, Alerts: alerts, Assets: assets, Precision: map[string]float64{},
		Attack: cat, Weights: risk.DefaultWeights, Bands: bands, WhatIf: map[string]int{"srv": 1}})
	if what.Current.Risk >= set.Current.Risk {
		t.Fatal("lowering criticality in a what-if must lower the score")
	}
}

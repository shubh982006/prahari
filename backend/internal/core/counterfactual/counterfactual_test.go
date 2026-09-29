package counterfactual

import (
	"strings"
	"testing"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/risk"
	"prahari/internal/domain"
)

func catalog(t *testing.T) *attack.Catalog {
	t.Helper()
	cat, err := attack.LoadFile("../../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestBoundaryLandsOnTheBandEdge(t *testing.T) {
	cat := catalog(t)
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

// breach is a four-stage chain (initial access → execution → lateral movement
// → exfiltration) that reaches fin, a pii/financial host, so it trips the
// compliance trigger. Every alert is high rather than critical, so the P1
// floor does not apply and each counterfactual is free to move the priority.
func breach() ([]domain.Alert, map[string]domain.Asset) {
	t0 := time.Date(2026, 9, 29, 4, 0, 0, 0, time.UTC)
	at := func(id string, m int, tech, rule string, hosts ...string) domain.Alert {
		return domain.Alert{ID: id, TS: t0.Add(time.Duration(m) * time.Minute), Severity: domain.SevHigh,
			TechniqueID: tech, RuleID: rule, Entities: domain.Entities{Hosts: hosts}}
	}
	alerts := []domain.Alert{
		at("a1", 0, "T1566.001", "R1", "ws-1"),
		at("a2", 1, "T1059.001", "R2", "ws-1"),
		at("a3", 2, "T1021.001", "R3", "ws-1", "fin"),
		at("a4", 3, "T1041", "R4", "fin"),
	}
	assets := map[string]domain.Asset{
		"ws-1": {Hostname: "ws-1", Criticality: 3, DataClasses: []string{}},
		"fin":  {Hostname: "fin", Criticality: 6, DataClasses: []string{"pii", "financial"}},
	}
	return alerts, assets
}

var breachBands = domain.Bands{P1: 85, P2: 60, P3: 30}

func computeBreach(t *testing.T, hasCase bool) (Set, []domain.Alert, map[string]domain.Asset) {
	t.Helper()
	alerts, assets := breach()
	set := Compute(Input{Incident: domain.Incident{ID: "INC-1"}, Alerts: alerts, Assets: assets,
		Precision: map[string]float64{}, Attack: catalog(t), Weights: risk.DefaultWeights, Bands: breachBands, HasCase: hasCase})
	if set.Current.Priority != "P1" || set.Current.Override != "" {
		t.Fatalf("setup: want P1 without the floor, got %+v", set.Current)
	}
	return set, alerts, assets
}

func find(t *testing.T, set Set, match func(Item) bool, what string) Item {
	t.Helper()
	for _, it := range set.Counterfactuals {
		if match(it) {
			return it
		}
	}
	t.Fatalf("no %s counterfactual in %v", what, set.Counterfactuals)
	return nil
}

// checkScored asserts an item's risk, priority and delta agree with an
// independent recomputation of the score.
func checkScored(t *testing.T, set Set, it Item, want float64) {
	t.Helper()
	if it["risk"] != want {
		t.Errorf("%s: risk %v, want %v", it["label"], it["risk"], want)
	}
	if p := breachBands.Priority(want); it["priority"] != p {
		t.Errorf("%s: priority %v, want %v", it["label"], it["priority"], p)
	}
	if d := risk.Round2(want - set.Current.Risk); it["delta"] != d {
		t.Errorf("%s: delta %v, want %v", it["label"], it["delta"], d)
	}
}

func TestFactorCounterfactualsSubstituteOneFactor(t *testing.T) {
	set, _, _ := computeBreach(t, true)
	f := set.Current.Factors
	w := risk.DefaultWeights

	c := find(t, set, func(it Item) bool { return it["kind"] == "factor" && it["factor"] == "C" }, "factor C")
	if want := risk.Round2(risk.ChainFactor(3)); c["value"] != want {
		t.Errorf("C value %v, want %v (forward path cut from 4 stages to 3)", c["value"], want)
	}
	if !strings.Contains(c["label"].(string), "lateral movement") {
		t.Errorf("C label should name where the chain stops: %q", c["label"])
	}
	checkScored(t, set, c, risk.Score(c["value"].(float64), f["S"], f["A"], f["Q"], w))

	s := find(t, set, func(it Item) bool { return it["kind"] == "factor" && it["factor"] == "S" }, "factor S")
	if want := risk.Round2(0.5*domain.SevMedium.Score() + 0.5*6.0/6); s["value"] != want {
		t.Errorf("S value %v, want %v", s["value"], want)
	}
	checkScored(t, set, s, risk.Score(f["C"], s["value"].(float64), f["A"], f["Q"], w))

	q := find(t, set, func(it Item) bool { return it["kind"] == "factor" && it["factor"] == "Q" }, "factor Q")
	if q["value"] != 0.30 {
		t.Errorf("Q value %v", q["value"])
	}
	checkScored(t, set, q, risk.Score(f["C"], f["S"], f["A"], 0.30, w))
	if q["priority"] == "P1" {
		t.Errorf("confidence 0.30 should drop this incident out of P1: %v", q)
	}
}

func TestAssetCounterfactualsRecomputeImpact(t *testing.T) {
	set, _, _ := computeBreach(t, true)
	f := set.Current.Factors
	w := risk.DefaultWeights

	untag := find(t, set, func(it Item) bool { return it["label"] == "if fin were not tagged pii or financial" }, "untag fin")
	// fin keeps criticality 6 but loses the +0.2 uplift; ws-1 is 3, so A = 0.6
	checkScored(t, set, untag, risk.Score(f["C"], f["S"], 0.6, f["Q"], w))

	ws := find(t, set, func(it Item) bool { return it["label"] == "if fin were an ordinary workstation (criticality 3)" }, "demote fin")
	checkScored(t, set, ws, risk.Score(f["C"], f["S"], 0.3, f["Q"], w))

	// ws-1 is already criticality 3 and untagged: there is nothing to offer about it
	for _, it := range set.Counterfactuals {
		if it["kind"] == "asset" && strings.Contains(it["label"].(string), "ws-1") {
			t.Errorf("asset counterfactual on a host that cannot change: %v", it)
		}
	}
}

func TestAlertRemovalRecomputesEverything(t *testing.T) {
	set, alerts, assets := computeBreach(t, true)
	exfil := find(t, set, func(it Item) bool { return it["kind"] == "alert" && it["alert_id"] == "a4" }, "remove a4")
	ctx := risk.Context{Assets: assets, Weights: risk.DefaultWeights, Precision: func(string) float64 { return 0.5 }}
	rest := risk.Evaluate(correlate.Members(alerts[:3], catalog(t)), ctx)
	if rest.MaxStage != 4 || rest.ForwardStages != 3 {
		t.Fatalf("setup: without a4 the chain should be 3 stages topping out at 4, got %d/%d", rest.ForwardStages, rest.MaxStage)
	}
	checkScored(t, set, exfil, rest.Risk)

	// Ranked: evidence that closes the case first, then by largest drop.
	seenOpen := false
	for _, it := range set.Counterfactuals {
		if it["kind"] != "alert" {
			continue
		}
		if it["closes_case"] == false {
			seenOpen = true
		} else if seenOpen {
			t.Fatalf("alert items not ranked closes_case-first: %v", set.Counterfactuals)
		}
	}
}

func TestClosesCase(t *testing.T) {
	set, _, _ := computeBreach(t, true)
	want := map[string]bool{
		"factor C": true,  // chain stops at stage 4, below the stage-5 trigger
		"factor S": false, // still P1 at stage 6 on fin
		"factor Q": false, // P2 still triggers
		"if fin were not tagged pii or financial":             true, // no sensitive asset left
		"if fin were an ordinary workstation (criticality 3)": true,
		"remove a4": true, // the only exfiltration alert
	}
	for _, it := range set.Counterfactuals {
		key := it["label"].(string)
		if it["kind"] == "factor" {
			key = "factor " + it["factor"].(string)
		}
		w, ok := want[key]
		if !ok {
			continue
		}
		delete(want, key)
		if it["closes_case"] != w {
			t.Errorf("%s: closes_case %v, want %v", key, it["closes_case"], w)
		}
	}
	for k := range want {
		t.Errorf("missing counterfactual %q", k)
	}

	// Without an open case there is no clock to stop.
	none, _, _ := computeBreach(t, false)
	for _, it := range none.Counterfactuals {
		if it["kind"] != "boundary" && it["closes_case"] != false {
			t.Errorf("no case, yet %q closes one", it["label"])
		}
	}
}

func TestP1FloorIsReportedNotSolved(t *testing.T) {
	alerts, assets := breach()
	alerts[3].Severity = domain.SevCritical
	fin := assets["fin"]
	fin.Criticality = 9
	assets["fin"] = fin
	set := Compute(Input{Incident: domain.Incident{ID: "INC-1"}, Alerts: alerts, Assets: assets,
		Precision: map[string]float64{}, Attack: catalog(t), Weights: risk.DefaultWeights, Bands: domain.Bands{P1: 99.9, P2: 60, P3: 30}})
	if set.Current.Override == "" || set.Current.Priority != "P1" {
		t.Fatalf("setup: want the P1 floor, got %+v", set.Current)
	}
	for _, it := range set.Counterfactuals {
		switch it["kind"] {
		case "factor":
			if it["priority"] != "P1" {
				t.Errorf("factor change escaped the P1 floor: %v", it)
			}
		case "boundary":
			if it["reachable"] != false || it["target_value"] != nil {
				t.Errorf("boundary under the floor must be unreachable: %v", it)
			}
		}
	}
}

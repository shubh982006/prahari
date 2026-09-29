package evade

import (
	"reflect"
	"testing"
	"time"

	"prahari/internal/core/simulate"
)

func params() Params {
	return Params{LinkWindow: 2 * time.Hour, SupernodeRatio: 0.05, SupernodeMinDF: 20, FloodTarget: "pay-db-01"}
}

func TestGeneratorsAreReproducible(t *testing.T) {
	sim := simulate.Generate(simulate.Params{Seed: 3})
	base := sim.All()
	for _, s := range Strategies {
		a, _ := Generate(base, sim.Truth, s, 0.6, 9, params(), "ds_v")
		b, _ := Generate(base, sim.Truth, s, 0.6, 9, params(), "ds_v")
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: same seed, different adversary", s)
		}
	}
}

func TestZeroBudgetChangesNothing(t *testing.T) {
	sim := simulate.Generate(simulate.Params{Seed: 3})
	base := sim.All()
	for _, s := range Strategies {
		v, _ := Generate(base, sim.Truth, s, 0, 9, params(), sim.DatasetID)
		if !reflect.DeepEqual(v.Alerts, base) {
			t.Fatalf("%s at β=0 mutated the dataset", s)
		}
	}
}

func TestBaseIsNeverMutated(t *testing.T) {
	sim := simulate.Generate(simulate.Params{Seed: 3})
	base := sim.All()
	snapshot := simulate.Generate(simulate.Params{Seed: 3}).All()
	for _, s := range Strategies {
		_, _ = Generate(base, sim.Truth, s, 1, 9, params(), "ds_v")
	}
	if !reflect.DeepEqual(base, snapshot) {
		t.Fatal("a generator mutated the base dataset")
	}
}

func TestDilationStretchesGapsPastTheWindow(t *testing.T) {
	sim := simulate.Generate(simulate.Params{Seed: 3})
	v, _ := Generate(sim.All(), sim.Truth, TemporalDilation, 1, 9, params(), "ds_v")
	byID := map[string]time.Time{}
	for _, a := range v.Alerts {
		byID[a.ID] = a.TS
	}
	steps := v.Truth.Scenarios[0].Steps
	var longest time.Duration
	for k := 1; k < len(steps); k++ {
		longest = max(longest, byID[steps[k][0]].Sub(byID[steps[k-1][len(steps[k-1])-1]]))
	}
	if longest <= 2*time.Hour {
		t.Fatalf("at β=1 some gap should exceed the 2h window, longest %s", longest)
	}
}

func TestCrossesFloor(t *testing.T) {
	b := []float64{0, 0.25, 0.5, 0.75, 1}
	if x := CrossesFloor(b, []float64{1, 1, 0.5, 0, 0}, 0.7); x == nil || *x != 0.4 {
		t.Fatalf("got %v, want 0.4", x)
	}
	if x := CrossesFloor(b, []float64{1, 1, 1, 1, 0.9}, 0.7); x != nil {
		t.Fatal("a series that never drops below the floor has no crossing")
	}
}

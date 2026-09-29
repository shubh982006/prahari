package risk

import (
	"math"
	"testing"

	"prahari/internal/domain"
)

func TestScoreMatchesContractExample(t *testing.T) {
	// api-contract §7: C=1, S=1, A=1, Q=0.93 scores 98.92
	if got := Score(1, 1, 1, 0.93, DefaultWeights); got != 98.92 {
		t.Fatalf("got %v, want 98.92", got)
	}
}

// design §8.2: a complete chain (C=1, S=1, Q=0.93) swept across criticality.
func TestCriticalitySweep(t *testing.T) {
	cases := []struct {
		a    float64
		want float64
	}{{1.0, 98.9}, {0.7, 88.9}, {0.5, 80.3}, {0.3, 68.9}, {0.2, 61.0}, {0.1, 49.6}} // one decimal, as published
	for _, c := range cases {
		got := Score(1, 1, c.a, 0.93, DefaultWeights)
		if math.Abs(got-c.want) > 0.05 {
			t.Errorf("A=%.1f: got %.2f, want %.2f", c.a, got, c.want)
		}
	}
}

func TestGeometricMeanCannotHideAZero(t *testing.T) {
	if got := Score(1, 1, 0, 1, DefaultWeights); got != 0 {
		t.Fatalf("a zero factor must zero the score, got %v", got)
	}
}

func TestForwardPath(t *testing.T) {
	cases := []struct {
		stages []int
		n      int
	}{
		{nil, 0},
		{[]int{3}, 1},
		{[]int{1, 2, 4, 6}, 4},
		{[]int{3, 1, 2, 5, 3, 4, 4, 5, 6}, 6}, // 1,2,3,4,5,6: out-of-order steps are skipped
		{[]int{4, 4, 4, 4}, 1},                // strictly increasing: repeats do not count
		{[]int{6, 5, 4, 3}, 1},
	}
	for _, c := range cases {
		n, path := ForwardPath(c.stages)
		if n != c.n || len(path) != c.n {
			t.Errorf("%v: got %d (%v), want %d", c.stages, n, path, c.n)
			continue
		}
		for i := 1; i < len(path); i++ {
			if path[i] <= path[i-1] || c.stages[path[i]] <= c.stages[path[i-1]] {
				t.Errorf("%v: path %v is not strictly increasing in time and stage", c.stages, path)
			}
		}
	}
}

func TestChainFactor(t *testing.T) {
	for lis, want := range map[int]float64{0: 0.2, 1: 0.2, 2: 0.4667, 3: 0.7333, 4: 1, 7: 1} {
		if got := ChainFactor(lis); math.Abs(got-want) > 1e-3 {
			t.Errorf("LIS %d: got %v, want %v", lis, got, want)
		}
	}
}

func TestCalibrateSizesBandsToCapacity(t *testing.T) {
	scores := []float64{99, 97, 95, 93, 91, 89, 87, 85, 83, 81, 79, 77, 75, 73, 71, 69, 60, 50, 40, 30}
	b := Calibrate(scores, Capacity{P1PerShift: 5, P2PerShift: 10})
	if b.P1 != 91 || b.P2 != 71 {
		t.Fatalf("bands %+v: want P1=91 (5th), P2=71 (15th)", b)
	}
	p1 := 0
	for _, s := range scores {
		if b.Priority(s) == "P1" {
			p1++
		}
	}
	if p1 != 5 {
		t.Fatalf("P1 holds %d incidents, want capacity 5", p1)
	}
}

func TestCalibrateClampsTinyDatasets(t *testing.T) {
	b := Calibrate([]float64{12}, DefaultCapacity)
	if b.P1 < 60 || b.P2 < 40 || b.P3 < 20 {
		t.Fatalf("a single low score must not become P1: %+v", b)
	}
	if b := Calibrate(nil, DefaultCapacity); b.P1 != 60 {
		t.Fatalf("empty run: %+v", b)
	}
}

func TestOverrideFloorsCriticalExfilOnCrownJewel(t *testing.T) {
	assets := map[string]domain.Asset{"fin-db-01": {Hostname: "fin-db-01", Criticality: 9, DataClasses: []string{"pii"}}}
	ms := []Member{{ID: "a", Severity: domain.SevCritical, Stage: 6, Tactic: "Exfiltration", RuleID: "R", Hosts: []string{"fin-db-01"}}}
	r := Evaluate(ms, Context{Assets: assets, Weights: DefaultWeights, Precision: func(string) float64 { return 0.1 }})
	if r.Override == "" || Priority(r, domain.Bands{P1: 99, P2: 98, P3: 97}) != "P1" {
		t.Fatalf("critical stage-6 alert on a criticality-9 asset must floor at P1: %+v", r)
	}
}

func TestAssetFactor(t *testing.T) {
	assets := map[string]domain.Asset{
		"dc01":      {Hostname: "dc01", Criticality: 10, DataClasses: []string{"credentials"}},
		"fin-db-01": {Hostname: "fin-db-01", Criticality: 9, DataClasses: []string{"pii", "financial"}},
		"ws-1":      {Hostname: "ws-1", Criticality: 2},
	}
	m := func(h ...string) []Member { return []Member{{Hosts: h}} }
	for _, c := range []struct {
		hosts []string
		want  float64
	}{
		{nil, 0.3}, {[]string{"unknown-host"}, 0.3}, {[]string{"ws-1"}, 0.2},
		{[]string{"fin-db-01"}, 1.0}, {[]string{"ws-1", "dc01"}, 1.0},
	} {
		got, _, _ := AssetFactor(m(c.hosts...), assets)
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("%v: got %v, want %v", c.hosts, got, c.want)
		}
	}
}

func TestSolveFactorIsExactAndHonest(t *testing.T) {
	v, ok := SolveFactor("A", 84.10, 1, 1, 1, 0.93, DefaultWeights)
	if !ok {
		t.Fatal("A should be reachable")
	}
	if got := Score(1, 1, v, 0.93, DefaultWeights); math.Abs(got-84.10) > 0.01 {
		t.Fatalf("solved A=%v scores %v, want 84.10", v, got)
	}
	// with C at its floor, no severity in [0,1] reaches 99
	if _, ok := SolveFactor("S", 99, 0.2, 1, 1, 1, DefaultWeights); ok {
		t.Fatal("unreachable targets must be reported as unreachable, not clamped")
	}
}

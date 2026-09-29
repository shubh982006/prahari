package correlate_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"testing/quick"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/entity"
	"prahari/internal/core/receipt"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

var update = flag.Bool("update", false, "rewrite golden files")

var catalog *attack.Catalog

func TestMain(m *testing.M) {
	var err error
	catalog, err = attack.LoadFile("../../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func input(alerts []domain.Alert, cfg correlate.Config) correlate.Input {
	assets := map[string]domain.Asset{}
	for _, a := range simulate.CMDB() {
		assets[a.Hostname] = a
	}
	stats := map[string]domain.RuleStat{}
	for _, r := range simulate.AllRuleStats() {
		stats[r.RuleID] = r
	}
	return correlate.Input{DatasetID: "ds_test", Alerts: alerts, Assets: assets, RuleStats: stats, Attack: catalog, Config: cfg,
		RunStarted: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}
}

func run(t testing.TB, alerts []domain.Alert, cfg correlate.Config) correlate.Output {
	out, err := correlate.Run(input(alerts, cfg), correlate.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// partition renders the incident membership canonically.
func partition(incs []domain.Incident) string {
	var groups []string
	for _, inc := range incs {
		ids := append([]string(nil), inc.AlertIDs...)
		sort.Strings(ids)
		groups = append(groups, fmt.Sprint(ids))
	}
	sort.Strings(groups)
	return fmt.Sprint(groups)
}

// Consecutive-pair linking must give the same components as all-pairs
// linking, because connectivity is transitive. Checked over random inputs
// with the laundering pass off (it is a separate, second pass).
func TestConsecutiveLinkingEqualsAllPairs(t *testing.T) {
	cfg := correlate.DefaultConfig()
	cfg.LaunderingPass = false
	cfg.SupernodeRatio, cfg.SupernodeMinDF = 0.5, 1_000_000 // no stop-list, so all-pairs is simple to state
	f := func(seed int64) bool {
		rng := rand.New(rand.NewPCG(uint64(seed), 7))
		n := 20 + rng.IntN(60)
		var alerts []domain.Alert
		for i := 0; i < n; i++ {
			alerts = append(alerts, domain.Alert{ID: fmt.Sprintf("A%03d", i),
				TS:       time.Unix(1_790_000_000+int64(rng.IntN(6*3600)), 0).UTC(),
				RuleID:   "R", RuleName: "r", Severity: domain.SevLow, Source: "edr",
				Entities: domain.Entities{Users: []string{fmt.Sprintf("u%d", rng.IntN(8))}, Hosts: []string{fmt.Sprintf("h%d", rng.IntN(8))}}})
		}
		got := partition(run(t, alerts, cfg).Incidents)
		// all pairs
		parent := map[string]string{}
		var find func(string) string
		find = func(x string) string {
			if parent[x] == "" || parent[x] == x {
				parent[x] = x
				return x
			}
			parent[x] = find(parent[x])
			return parent[x]
		}
		for i := range alerts {
			for j := i + 1; j < len(alerts); j++ {
				d := alerts[i].TS.Sub(alerts[j].TS)
				if d < 0 {
					d = -d
				}
				if d > cfg.LinkWindow {
					continue
				}
				ki, kj := entity.Keys(alerts[i].Entities), entity.Keys(alerts[j].Entities)
				shared := false
				for _, a := range ki {
					for _, b := range kj {
						shared = shared || a == b
					}
				}
				if shared {
					parent[find(alerts[i].ID)] = find(alerts[j].ID)
				}
			}
		}
		groups := map[string][]string{}
		for _, a := range alerts {
			r := find(a.ID)
			groups[r] = append(groups[r], a.ID)
		}
		var want []string
		for _, g := range groups {
			sort.Strings(g)
			want = append(want, fmt.Sprint(g))
		}
		sort.Strings(want)
		return got == fmt.Sprint(want)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}

// Input order must not matter: the engine sorts, and no map iteration leaks
// into the output.
func TestDeterministicUnderShuffle(t *testing.T) {
	alerts := simulate.Generate(simulate.Params{Seed: 5}).All()
	cfg := correlate.DefaultConfig()
	want := receipt.OutputHash(run(t, alerts, cfg).Incidents)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5; i++ {
		shuffled := append([]domain.Alert(nil), alerts...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := receipt.OutputHash(run(t, shuffled, cfg).Incidents); got != want {
			t.Fatalf("shuffle %d changed the output hash", i)
		}
	}
}

type golden struct {
	Bands     domain.Bands `json:"bands"`
	Incidents []struct {
		ID       string  `json:"id"`
		Priority string  `json:"priority"`
		Risk     float64 `json:"risk"`
		Cohesion string  `json:"cohesion"`
		Label    string  `json:"label"`
		Alerts   int     `json:"alerts"`
	} `json:"top_incidents"`
	OutputHash string `json:"output_hash"`
}

// Seed 42 pins exact incidents, priorities, risks and cohesion. Refresh
// deliberately with: go test ./internal/core/correlate -run Golden -update
func TestGoldenSeed42(t *testing.T) {
	sim := simulate.Generate(simulate.Params{Seed: 42})
	out := run(t, sim.All(), correlate.DefaultConfig())
	var g golden
	g.Bands = out.Bands
	g.OutputHash = receipt.OutputHash(out.Incidents)
	for _, inc := range out.Incidents[:20] {
		g.Incidents = append(g.Incidents, struct {
			ID       string  `json:"id"`
			Priority string  `json:"priority"`
			Risk     float64 `json:"risk"`
			Cohesion string  `json:"cohesion"`
			Label    string  `json:"label"`
			Alerts   int     `json:"alerts"`
		}{inc.ID, inc.Priority, inc.Risk, inc.Cohesion, inc.Label, len(inc.AlertIDs)})
	}
	got, _ := json.MarshalIndent(g, "", "  ")
	path := filepath.Join("testdata", "golden_seed42.json")
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file; run with -update: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("seed 42 output changed. If intended, run with -update.\n--- got\n%s", got)
	}
}

func TestPlantedScenariosAreFoundAndMissesAreMissed(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		sim := simulate.Generate(simulate.Params{Seed: seed})
		out := run(t, sim.All(), correlate.DefaultConfig())
		incOf := map[string]string{}
		for _, inc := range out.Incidents {
			for _, a := range inc.AlertIDs {
				incOf[a] = inc.ID
			}
		}
		for _, sc := range sim.Truth.Scenarios {
			count := map[string]int{}
			best := 0
			for _, a := range sc.AlertIDs {
				count[incOf[a]]++
				best = max(best, count[incOf[a]])
			}
			detected := float64(best) >= 0.7*float64(len(sc.AlertIDs))
			if detected == (sc.DeliberateMiss != "") {
				t.Errorf("seed %d scenario %s: detected=%v, deliberate miss=%q", seed, sc.Scenario, detected, sc.DeliberateMiss)
			}
		}
	}
}

func TestSuppressionAndCutsChangeOutput(t *testing.T) {
	sim := simulate.Generate(simulate.Params{Seed: 42})
	alerts := sim.All()
	cfg := correlate.DefaultConfig()
	base := run(t, alerts, cfg)
	top := base.Incidents[0]
	if len(top.BridgeEdges) == 0 {
		t.Skip("top incident has no bridge on this seed")
	}
	cfg.Cuts = []domain.Cut{{AlertA: top.BridgeEdges[0].AlertA, AlertB: top.BridgeEdges[0].AlertB}}
	cut := run(t, alerts, cfg)
	if receipt.OutputHash(cut.Incidents) == receipt.OutputHash(base.Incidents) {
		t.Fatal("a cut along a bridge must change the incidents")
	}
	if len(cut.Incidents) != len(base.Incidents)+1 {
		t.Fatalf("cutting a bridge should add exactly one incident: %d → %d", len(base.Incidents), len(cut.Incidents))
	}
	in := input(alerts, correlate.DefaultConfig())
	in.Suppressed = []domain.Suppression{{RuleID: "NET-PORTSCAN", EntityKey: "host:vscan01"}}
	sup, _ := correlate.Run(in, correlate.Hooks{})
	if sup.AlertsSuppressed == 0 {
		t.Fatal("suppression dropped nothing")
	}
}

func TestCancellationStopsTheRun(t *testing.T) {
	alerts := simulate.Generate(simulate.Params{Seed: 1}).All()
	calls := 0
	_, err := correlate.Run(input(alerts, correlate.DefaultConfig()), correlate.Hooks{Cancelled: func() bool { calls++; return calls > 2 }})
	if err != correlate.ErrCancelled {
		t.Fatalf("got %v", err)
	}
}

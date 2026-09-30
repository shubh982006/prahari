package correlate

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/cohesion"
	"prahari/internal/core/entity"
	"prahari/internal/core/receipt"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

// The indexed bridge similarity must equal the direct definition exactly —
// same float, not just close — on every bridge the cohesion stage asks about,
// and the whole run's output must be identical either way. Checked on real
// simulated days and on a multi-day window with the large recurring
// components that made the direct version quadratic.
func TestIndexedSimilarityEqualsDirect(t *testing.T) {
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
	run := func(alerts []domain.Alert) Output {
		out, err := Run(Input{DatasetID: "ds_test", Alerts: alerts, Assets: assets, RuleStats: stats, Attack: cat,
			Config: DefaultConfig(), RunStarted: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}, Hooks{})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	multiDay := func(days int) []domain.Alert {
		var out []domain.Alert
		for d := 0; d < days; d++ {
			r := simulate.Generate(simulate.Params{Seed: int64(1000 + d), Start: simulate.DefaultStart.Add(time.Duration(d) * 24 * time.Hour)})
			for _, a := range r.All() {
				a.ID = fmt.Sprintf("D%d-%s", d, a.ID)
				out = append(out, a)
			}
		}
		return out
	}
	cases := map[string][]domain.Alert{}
	for _, seed := range []int64{1, 2, 3, 4, 5, 42} {
		cases[fmt.Sprintf("seed=%d", seed)] = simulate.Generate(simulate.Params{Seed: seed}).All()
	}
	cases["days=10"] = multiDay(10)

	orig := bridgeSimilarity
	defer func() { bridgeSimilarity = orig }()
	total := 0
	for name, alerts := range cases {
		calls := 0
		bridgeSimilarity = func(b *build, nodes []node, idx *entity.Index, br cohesion.Bridge) float64 {
			fast, direct := b.similarity(nodes, idx, br), b.similarityDirect(nodes, idx, br)
			if fast != direct {
				t.Errorf("%s: bridge %d of %s: indexed %v, direct %v", name, br.Edge, b.id, fast, direct)
			}
			calls++
			return direct
		}
		direct := run(alerts)
		bridgeSimilarity = orig
		fast := run(alerts)
		if !reflect.DeepEqual(direct.Incidents, fast.Incidents) {
			t.Errorf("%s: incidents differ between direct and indexed similarity", name)
		}
		if a, b := receipt.OutputHash(direct.Incidents), receipt.OutputHash(fast.Incidents); a != b {
			t.Errorf("%s: output hash %s (direct) vs %s (indexed)", name, a, b)
		}
		t.Logf("%s: %d alerts, %d bridge comparisons, all equal", name, len(alerts), calls)
		total += calls
	}
	if total == 0 {
		t.Fatal("no bridge was compared: the test exercised nothing")
	}
}

// Random connected graphs with random entity sets, including stop-listed and
// once-seen entities: the index must agree with the definition on every
// bridge, whatever the shape.
func TestSideIndexOnRandomGraphs(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	checked := 0
	for trial := 0; trial < 500; trial++ {
		n := 2 + rng.IntN(40)
		// a random spanning tree plus a few extra edges, never parallel
		type pair struct{ u, v int }
		have := map[pair]bool{}
		var ge []cohesion.Edge
		add := func(u, v int) {
			if u == v {
				return
			}
			p := pair{min(u, v), max(u, v)}
			if have[p] {
				return
			}
			have[p] = true
			ge = append(ge, cohesion.Edge{U: p.u, V: p.v, Weight: 1})
		}
		for v := 1; v < n; v++ {
			add(rng.IntN(v), v)
		}
		for i := rng.IntN(n/2 + 1); i > 0; i-- {
			add(rng.IntN(n), rng.IntN(n))
		}
		// shuffle edge order so the index's tree differs from Tarjan's DFS tree
		rng.Shuffle(len(ge), func(i, j int) { ge[i], ge[j] = ge[j], ge[i] })
		idx := &entity.Index{DF: map[string]int{}, Stoplist: map[string]bool{"k:stop": true}}
		nodes := make([]node, n)
		members := make([]int, n)
		for i := range nodes {
			members[i] = i
			for j := rng.IntN(5); j > 0; j-- {
				k := fmt.Sprintf("k:%d", rng.IntN(12))
				if rng.IntN(10) == 0 {
					k = "k:stop"
				}
				nodes[i].keys = append(nodes[i].keys, k)
			}
			for _, k := range nodes[i].keys {
				idx.DF[k]++
			}
		}
		idx.DF["k:0"] = 1 // a once-seen entity is not linkable, whatever its holders
		b := &build{nodes: members, graph: cohesion.NewGraph(n, ge)}
		for _, br := range cohesion.Bridges(b.graph) {
			fast, direct := b.similarity(nodes, idx, br), b.similarityDirect(nodes, idx, br)
			if fast != direct {
				t.Fatalf("trial %d, bridge %v: indexed %v, direct %v", trial, br, fast, direct)
			}
			checked++
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d bridges checked", checked)
	}
}

// BenchmarkSimilarity runs the whole engine with the direct and the indexed
// bridge similarity back to back, so the comparison shares one machine state.
//
//	go test ./internal/core/correlate -run '^$' -bench Similarity -benchtime 5x -count 3
func BenchmarkSimilarity(b *testing.B) {
	cat, err := attack.LoadFile("../../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		b.Fatal(err)
	}
	assets := map[string]domain.Asset{}
	for _, a := range simulate.CMDB() {
		assets[a.Hostname] = a
	}
	for _, days := range []int{2, 25} {
		var alerts []domain.Alert
		for d := 0; d < days; d++ {
			r := simulate.Generate(simulate.Params{Seed: int64(1000 + d), Start: simulate.DefaultStart.Add(time.Duration(d) * 24 * time.Hour)})
			for _, a := range r.All() {
				a.ID = fmt.Sprintf("D%d-%s", d, a.ID)
				alerts = append(alerts, a)
			}
		}
		in := Input{DatasetID: "ds_test", Alerts: alerts, Assets: assets, Attack: cat, Config: DefaultConfig(),
			RunStarted: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)}
		for _, impl := range []struct {
			name string
			fn   func(*build, []node, *entity.Index, cohesion.Bridge) float64
		}{{"direct", (*build).similarityDirect}, {"indexed", (*build).similarity}} {
			b.Run(fmt.Sprintf("alerts=%d/%s", len(alerts), impl.name), func(b *testing.B) {
				orig := bridgeSimilarity
				bridgeSimilarity = impl.fn
				defer func() { bridgeSimilarity = orig }()
				for i := 0; i < b.N; i++ {
					if _, err := Run(in, Hooks{}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

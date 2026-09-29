// Package correlate is the engine: a pipeline of pure stages that turns alerts
// into ranked incidents. It reads no clock, no database and no random source;
// RunStarted and every parameter are inputs. That is what makes the
// determinism receipt true on either storage dialect.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/cohesion"
	"prahari/internal/core/compliance"
	"prahari/internal/core/entity"
	"prahari/internal/core/risk"
	"prahari/internal/domain"
)

var ErrCancelled = errors.New("run cancelled")

// Techniques is the slice of the ATT&CK catalog the engine needs.
type Techniques interface {
	Lookup(id string) (attack.Technique, bool)
	TacticsForStage(stage int) []string
}

type Config struct {
	LinkWindow     time.Duration
	SupernodeRatio float64
	SupernodeMinDF int
	Weights        domain.Weights
	Capacity       risk.Capacity
	LaunderingPass bool
	BandMode       string // calibrated | fixed
	Cuts           []domain.Cut
}

func DefaultConfig() Config {
	return Config{
		LinkWindow:     2 * time.Hour,
		SupernodeRatio: 0.05,
		SupernodeMinDF: 20,
		Weights:        risk.DefaultWeights,
		Capacity:       risk.DefaultCapacity,
		LaunderingPass: true,
		BandMode:       "calibrated",
	}
}

// Canonical is the config as it appears in /meta, the run params and the
// receipt. Cuts are sorted so their order cannot change the hash.
func (c Config) Canonical() map[string]any {
	cuts := make([]domain.Cut, len(c.Cuts))
	copy(cuts, c.Cuts)
	for i := range cuts {
		if cuts[i].AlertA > cuts[i].AlertB {
			cuts[i].AlertA, cuts[i].AlertB = cuts[i].AlertB, cuts[i].AlertA
		}
	}
	sort.Slice(cuts, func(i, j int) bool {
		if cuts[i].AlertA != cuts[j].AlertA {
			return cuts[i].AlertA < cuts[j].AlertA
		}
		return cuts[i].AlertB < cuts[j].AlertB
	})
	return map[string]any{
		"link_window":      FormatDuration(c.LinkWindow),
		"supernode_ratio":  c.SupernodeRatio,
		"supernode_min_df": c.SupernodeMinDF,
		"weights":          map[string]float64{"C": c.Weights.C, "S": c.Weights.S, "A": c.Weights.A, "Q": c.Weights.Q},
		"capacity":         map[string]int{"p1_per_shift": c.Capacity.P1PerShift, "p2_per_shift": c.Capacity.P2PerShift},
		"laundering_pass":  c.LaunderingPass,
		"band_mode":        c.BandMode,
		"cuts":             cuts,
	}
}

// FormatDuration prints 2h, 90m or 45s rather than Go's 2h0m0s.
func FormatDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	}
	return d.String()
}

type Input struct {
	DatasetID  string
	Alerts     []domain.Alert
	Assets     map[string]domain.Asset
	RuleStats  map[string]domain.RuleStat
	Suppressed []domain.Suppression
	Attack     Techniques
	Config     Config
	RunStarted time.Time
}

// Stage is one progress report. The caller stamps elapsed time; the engine
// cannot, because it does not read a clock.
type Stage struct {
	Name  string
	Count int
}

type Hooks struct {
	Progress  func(Stage)
	Cancelled func() bool
}

type Output struct {
	Incidents        []domain.Incident
	Bands            domain.Bands
	AlertsIn         int
	AlertsSuppressed int
	EntityRefs       int
	Stoplist         []string
	LaunderingLinks  int
}

// node is one surviving alert.
type node struct {
	a      *domain.Alert
	keys   []string
	stage  int
	tactic string
	tname  string
	hosts  []string
}

// Run executes the pipeline.
func Run(in Input, h Hooks) (Output, error) {
	cfg := in.Config
	if cfg.LinkWindow == 0 {
		cfg = DefaultConfig()
	}
	emit := func(name string, count int) error {
		if h.Cancelled != nil && h.Cancelled() {
			return ErrCancelled
		}
		if h.Progress != nil {
			h.Progress(Stage{name, count})
		}
		return nil
	}
	out := Output{AlertsIn: len(in.Alerts)}

	// filter
	alerts := make([]domain.Alert, len(in.Alerts))
	copy(alerts, in.Alerts)
	SortAlerts(alerts)
	sup := map[string]bool{}
	for _, s := range in.Suppressed {
		if s.ExpiresAt == nil || s.ExpiresAt.After(in.RunStarted) {
			sup[s.RuleID+"\x00"+s.EntityKey] = true
		}
	}
	nodes := make([]node, 0, len(alerts))
	for i := range alerts {
		a := &alerts[i]
		keys := entity.Keys(a.Entities)
		suppressed := false
		for _, k := range keys {
			if sup[a.RuleID+"\x00"+k] {
				suppressed = true
				break
			}
		}
		if suppressed {
			out.AlertsSuppressed++
			continue
		}
		n := node{a: a, keys: keys, stage: -1}
		if t, ok := lookup(in.Attack, a.TechniqueID); ok {
			n.stage, n.tactic, n.tname = t.Stage, t.Tactic, t.Name
		}
		for _, hst := range a.Entities.Hosts {
			if v := entity.NormHost(hst); v != "" {
				n.hosts = append(n.hosts, v)
			}
		}
		nodes = append(nodes, n)
	}
	if err := emit("filter", len(nodes)); err != nil {
		return out, err
	}

	// entities
	keyLists := make([][]string, len(nodes))
	for i := range nodes {
		keyLists[i] = nodes[i].keys
		out.EntityRefs += len(nodes[i].keys)
	}
	idx := entity.Build(keyLists, cfg.SupernodeRatio, cfg.SupernodeMinDF)
	out.Stoplist = idx.SortedStoplist()
	if err := emit("entities", out.EntityRefs); err != nil {
		return out, err
	}

	// link: per entity, consecutive occurrences within the window. Because
	// union-find is transitive this yields the same components as all-pairs.
	pos := make(map[string]int, len(nodes))
	for i := range nodes {
		pos[nodes[i].a.ID] = i
	}
	cuts := map[[2]int]bool{}
	for _, c := range cfg.Cuts {
		a, okA := pos[c.AlertA]
		b, okB := pos[c.AlertB]
		if okA && okB {
			cuts[[2]int{min(a, b), max(a, b)}] = true
		}
	}
	byEntity := map[string][]int{}
	for i := range nodes {
		for _, k := range nodes[i].keys {
			if !idx.Stoplist[k] {
				byEntity[k] = append(byEntity[k], i)
			}
		}
	}
	entKeys := make([]string, 0, len(byEntity))
	for k := range byEntity {
		entKeys = append(entKeys, k)
	}
	sort.Strings(entKeys)
	var edges []link
	for _, k := range entKeys {
		occ := byEntity[k]
		for j := 1; j < len(occ); j++ {
			a, b := occ[j-1], occ[j]
			if nodes[b].a.TS.Sub(nodes[a].a.TS) > cfg.LinkWindow || cuts[[2]int{a, b}] {
				continue
			}
			edges = append(edges, link{a, b, k, false})
		}
	}
	if err := emit("link", len(edges)); err != nil {
		return out, err
	}

	// launder
	dsu := newDSU(len(nodes))
	for _, e := range edges {
		dsu.union(e.a, e.b)
	}
	if cfg.LaunderingPass {
		ledges := launder(nodes, dsu, idx, cfg, in, cuts)
		for _, e := range ledges {
			dsu.union(e.a, e.b)
		}
		edges = append(edges, ledges...)
		out.LaunderingLinks = len(ledges)
	}
	if err := emit("launder", out.LaunderingLinks); err != nil {
		return out, err
	}

	// group
	members := map[int][]int{}
	for i := range nodes {
		r := dsu.find(i)
		members[r] = append(members[r], i)
	}
	comps := make([][]int, 0, len(members))
	for _, m := range members {
		comps = append(comps, m) // already ascending, i.e. time order
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i][0] < comps[j][0] })
	compOf := make([]int, len(nodes))
	for ci, m := range comps {
		for _, n := range m {
			compOf[n] = ci
		}
	}
	compEdges := make([][]link, len(comps))
	for _, e := range edges {
		ci := compOf[e.a]
		compEdges[ci] = append(compEdges[ci], e)
	}
	if err := emit("group", len(comps)); err != nil {
		return out, err
	}

	// shape
	ctxBase := risk.Context{Assets: in.Assets, Weights: cfg.Weights, Precision: precision(in.RuleStats)}
	builds := make([]*build, len(comps))
	chains := 0
	for ci, m := range comps {
		b := &build{nodes: m, edges: compEdges[ci]}
		for _, e := range b.edges {
			if e.laundered {
				b.laundered = true
			}
		}
		ctx := ctxBase
		ctx.Laundered = b.laundered
		b.res = risk.Evaluate(members2(nodes, m), ctx)
		b.label = label(nodes, m, b.res.ForwardStages)
		if b.label == "attack_chain" {
			chains++
		}
		builds[ci] = b
	}
	assignIDs(in.DatasetID, nodes, builds)
	if err := emit("shape", chains); err != nil {
		return out, err
	}

	// cohesion
	fragile := 0
	for _, b := range builds {
		b.cohesion(nodes, idx)
		if b.grade == cohesion.Fragile {
			fragile++
		}
	}
	if err := emit("cohesion", fragile); err != nil {
		return out, err
	}

	// score
	scores := make([]float64, len(builds))
	for i, b := range builds {
		scores[i] = b.res.Risk
	}
	if cfg.BandMode == "fixed" {
		out.Bands = risk.FixedBands
	} else {
		out.Bands = risk.Calibrate(scores, cfg.Capacity)
	}
	p1 := 0
	for _, b := range builds {
		b.priority = risk.Priority(b.res, out.Bands)
		if b.priority == "P1" {
			p1++
		}
	}
	rank(builds)
	for _, b := range builds {
		if b.grade == cohesion.Fragile {
			b.preview(nodes, ctxBase, out.Bands, in.Attack)
		}
	}
	if err := emit("score", p1); err != nil {
		return out, err
	}

	// compliance
	breaches := 0
	for _, b := range builds {
		b.breach = compliance.Trigger(b.priority, b.res.MaxStage, b.res.Hosts, in.Assets)
		if b.breach != nil {
			breaches++
		}
	}
	if err := emit("compliance", breaches); err != nil {
		return out, err
	}

	out.Incidents = make([]domain.Incident, len(builds))
	for i, b := range builds {
		out.Incidents[i] = b.incident(nodes, idx, in.Attack, cfg)
	}
	return out, nil
}

// SortAlerts orders by (timestamp, id), the order every stage relies on.
func SortAlerts(a []domain.Alert) {
	sort.SliceStable(a, func(i, j int) bool {
		if !a[i].TS.Equal(a[j].TS) {
			return a[i].TS.Before(a[j].TS)
		}
		return a[i].ID < a[j].ID
	})
}

func lookup(t Techniques, id string) (attack.Technique, bool) {
	if t == nil || id == "" {
		return attack.Technique{}, false
	}
	return t.Lookup(id)
}

func precision(stats map[string]domain.RuleStat) func(string) float64 {
	return func(id string) float64 {
		if s, ok := stats[id]; ok {
			return s.Precision()
		}
		return 0.5 // Beta(1,1): no evidence either way
	}
}

// Members converts alerts into scoring members; exported for counterfactuals.
func Members(alerts []domain.Alert, t Techniques) []risk.Member {
	out := make([]risk.Member, len(alerts))
	for i, a := range alerts {
		m := risk.Member{ID: a.ID, TS: a.TS, Severity: a.Severity, Stage: -1, RuleID: a.RuleID}
		if tt, ok := lookup(t, a.TechniqueID); ok {
			m.Stage, m.Tactic = tt.Stage, tt.Tactic
		}
		for _, h := range a.Entities.Hosts {
			if v := entity.NormHost(h); v != "" {
				m.Hosts = append(m.Hosts, v)
			}
		}
		out[i] = m
	}
	return out
}

func members2(nodes []node, idx []int) []risk.Member {
	out := make([]risk.Member, len(idx))
	for i, n := range idx {
		nd := nodes[n]
		out[i] = risk.Member{ID: nd.a.ID, TS: nd.a.TS, Severity: nd.a.Severity, Stage: nd.stage,
			Tactic: nd.tactic, RuleID: nd.a.RuleID, Hosts: nd.hosts}
	}
	return out
}

func label(nodes []node, m []int, lis int) string {
	if lis >= 2 {
		return "attack_chain"
	}
	if len(m) >= 20 {
		count := map[string]int{}
		top := 0
		for _, n := range m {
			count[nodes[n].a.RuleID]++
			top = max(top, count[nodes[n].a.RuleID])
		}
		if float64(top) > 0.8*float64(len(m)) {
			return "noise_cluster"
		}
	}
	return "single"
}

// assignIDs gives each incident a content-derived ID: INC- plus the first 8
// hex of sha256(dataset || anchor), where the anchor is the earliest alert on
// the forward path. Colliding IDs widen to 12 hex.
func assignIDs(dataset string, nodes []node, builds []*build) {
	full := make([]string, len(builds))
	count := map[string]int{}
	for i, b := range builds {
		anchor := nodes[b.nodes[0]].a.ID
		if len(b.res.Chain) > 0 {
			anchor = nodes[b.nodes[b.res.Chain[0]]].a.ID
		}
		b.anchor = anchor
		s := sha256.Sum256([]byte(dataset + anchor))
		full[i] = hex.EncodeToString(s[:])
		count[full[i][:8]]++
	}
	for i, b := range builds {
		if count[full[i][:8]] > 1 {
			b.id = "INC-" + full[i][:12]
		} else {
			b.id = "INC-" + full[i][:8]
		}
	}
}

// IncidentID exposes the ID rule for callers that need it (split previews).
func IncidentID(dataset, anchor string) string {
	s := sha256.Sum256([]byte(dataset + anchor))
	return "INC-" + hex.EncodeToString(s[:])[:8]
}

// rank orders by priority band, then risk, then ID. The P1 floor can place a
// lower-scoring incident above higher-scoring P2s; that is intended.
func rank(builds []*build) {
	sort.SliceStable(builds, func(i, j int) bool {
		a, b := builds[i], builds[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		if a.res.Risk != b.res.Risk {
			return a.res.Risk > b.res.Risk
		}
		return a.id < b.id
	})
	for i, b := range builds {
		b.rank = i + 1
	}
}

type link struct {
	a, b      int
	key       string
	laundered bool
}

type dsu struct{ parent, size []int32 }

func newDSU(n int) *dsu {
	d := &dsu{parent: make([]int32, n), size: make([]int32, n)}
	for i := range d.parent {
		d.parent[i] = int32(i)
		d.size[i] = 1
	}
	return d
}

func (d *dsu) find(x int) int {
	i := int32(x)
	for d.parent[i] != i {
		d.parent[i] = d.parent[d.parent[i]] // path halving
		i = d.parent[i]
	}
	return int(i)
}

func (d *dsu) union(a, b int) {
	ra, rb := int32(d.find(a)), int32(d.find(b))
	if ra == rb {
		return
	}
	if d.size[ra] < d.size[rb] {
		ra, rb = rb, ra
	}
	d.parent[rb] = ra
	d.size[ra] += d.size[rb]
}

func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

package correlate

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"prahari/internal/core/attack"
	"prahari/internal/core/cohesion"
	"prahari/internal/core/entity"
	"prahari/internal/core/risk"
	"prahari/internal/domain"
)

const (
	maxBridgesReported = 10
	maxEntitiesListed  = 25
	maxGraphEdges      = 300
	maxHeadlineSteps   = 5
)

// build accumulates one incident through the stages.
type build struct {
	id        string
	anchor    string
	rank      int
	nodes     []int // indices into the run's nodes, time order
	edges     []link
	laundered bool
	res       risk.Result
	label     string
	priority  string

	grade    string
	reason   string
	graph    *cohesion.Graph
	bridges  []cohesion.Bridge
	local    map[int]int // run node index → local graph index
	previewV *domain.SplitPreview
	breach   *domain.BreachTrigger
	sides    *sideIndex // built on the first bridge comparison
}

// SameActivityJaccard is the entity-set similarity above which two halves of a
// bridge are treated as the same recurring activity.
const SameActivityJaccard = 0.5

// linkable reports whether an entity counts when comparing the two sides of a
// bridge: entities seen once link nothing and only add noise to the
// comparison (a scanner's random targets, spoofed senders).
func linkable(idx *entity.Index, k string) bool { return !idx.Stoplist[k] && idx.DF[k] >= 2 }

// bridgeSimilarity is the Jaccard index of the linkable entities on the two
// sides of a bridge. Tests swap in the direct definition to prove the indexed
// one returns identical values.
var bridgeSimilarity = (*build).similarity

// similarity answers from a per-component index built on first use, so each
// bridge costs O(1) instead of a pass over the whole component. That pass per
// bridge made the cohesion stage quadratic on large recurring components.
func (b *build) similarity(nodes []node, idx *entity.Index, br cohesion.Bridge) float64 {
	if b.sides == nil {
		b.sides = newSideIndex(b.graph, b.nodes, nodes, idx)
	}
	if v, ok := b.sides.jaccard(b.graph.Edges[br.Edge], br.Edge); ok {
		return v
	}
	return b.similarityDirect(nodes, idx, br)
}

// similarityDirect is the definition: collect both sides' entity sets and
// intersect them. O(component) per bridge. It is the fallback for a graph the
// index cannot answer (disconnected, which the group stage never produces)
// and the reference the tests hold the index to.
func (b *build) similarityDirect(nodes []node, idx *entity.Index, br cohesion.Bridge) float64 {
	e := b.graph.Edges[br.Edge]
	side := cohesion.Side(b.graph, e.U, br.Edge)
	left, right := map[string]bool{}, map[string]bool{}
	for i, n := range b.nodes {
		set := right
		if side[i] {
			set = left
		}
		for _, k := range nodes[n].keys {
			if linkable(idx, k) {
				set[k] = true
			}
		}
	}
	inter, union := 0, len(right)
	for k := range left {
		if right[k] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

// sideIndex holds, for every node of a spanning tree of one component, how
// many linkable entities of its subtree also occur outside it.
//
// Removing a bridge leaves two sides: a tree edge's lower subtree and the
// rest. Jaccard is symmetric in the sides, the union of both sides' entity
// sets is every linkable entity in the component, and an entity is on both
// sides exactly when 0 < (nodes in the subtree holding it) < (nodes in the
// component holding it). Subtree counts are merged small-to-large, so the
// whole index costs O(K log V) for K entity references.
type sideIndex struct {
	connected  bool
	total      int   // distinct linkable entities in the component
	shared     []int // per node: subtree entities that also occur outside it
	parentEdge []int // per node: tree edge to its parent, -1 at the root
}

func newSideIndex(g *cohesion.Graph, members []int, nodes []node, idx *entity.Index) *sideIndex {
	s := &sideIndex{shared: make([]int, g.N), parentEdge: make([]int, g.N)}
	adj := make([][][2]int, g.N) // neighbour, edge
	for i, e := range g.Edges {
		adj[e.U] = append(adj[e.U], [2]int{e.V, i})
		adj[e.V] = append(adj[e.V], [2]int{e.U, i})
	}
	for i := range s.parentEdge {
		s.parentEdge[i] = -1
	}
	if g.N == 0 {
		return s
	}
	seen := make([]bool, g.N)
	parent := make([]int, g.N)
	order := []int{0}
	seen[0], parent[0] = true, -1
	for q := 0; q < len(order); q++ {
		u := order[q]
		for _, h := range adj[u] {
			if !seen[h[0]] {
				seen[h[0]], parent[h[0]], s.parentEdge[h[0]] = true, u, h[1]
				order = append(order, h[0])
			}
		}
	}
	if s.connected = len(order) == g.N; !s.connected {
		return s
	}
	keys := make([][]string, g.N)
	count := map[string]int{}
	for i, n := range members {
		seenKey := map[string]bool{}
		for _, k := range nodes[n].keys {
			if linkable(idx, k) && !seenKey[k] {
				seenKey[k] = true
				keys[i] = append(keys[i], k)
				count[k]++
			}
		}
	}
	s.total = len(count)
	sub := make([]map[string]int, g.N)
	partial := make([]int, g.N) // keys in sub[u] held by fewer nodes than in the component
	for q := len(order) - 1; q >= 0; q-- {
		u := order[q]
		if sub[u] == nil {
			sub[u] = map[string]int{}
		}
		for _, k := range keys[u] {
			partial[u] += mergeKey(sub[u], k, 1, count[k])
		}
		s.shared[u] = partial[u]
		if p := parent[u]; p >= 0 {
			if sub[p] == nil {
				sub[p] = map[string]int{}
			}
			big, small := sub[p], sub[u]
			pb, ps := partial[p], partial[u]
			if len(small) > len(big) {
				big, small, pb = small, big, ps
			}
			for k, c := range small {
				pb += mergeKey(big, k, c, count[k])
			}
			sub[p], partial[p], sub[u] = big, pb, nil
		}
	}
	return s
}

// mergeKey adds c holders of k to m and returns the change in the number of
// keys of m that are held by fewer than all total holders.
func mergeKey(m map[string]int, k string, c, total int) int {
	before := m[k]
	after := before + c
	m[k] = after
	d := 0
	if before > 0 && before < total {
		d--
	}
	if after < total {
		d++
	}
	return d
}

// jaccard returns the similarity across a bridge, or false when the index
// cannot answer (the graph is disconnected, or the edge is not a tree edge,
// which a bridge of a connected graph always is).
func (s *sideIndex) jaccard(e cohesion.Edge, edge int) (float64, bool) {
	child := -1
	switch {
	case s.parentEdge[e.U] == edge:
		child = e.U
	case s.parentEdge[e.V] == edge:
		child = e.V
	}
	if !s.connected || child < 0 {
		return 0, false
	}
	if s.total == 0 {
		return 1, true
	}
	return float64(s.shared[child]) / float64(s.total), true
}

func (b *build) cohesion(nodes []node, idx *entity.Index) {
	b.local = make(map[int]int, len(b.nodes))
	for i, n := range b.nodes {
		b.local[n] = i
	}
	// Collapse parallel links: two alerts sharing a host and that host's IP are
	// one piece of evidence, not two. Cohesion asks whether a single
	// alert-to-alert link holds the incident together, so each alert pair is
	// one edge carrying its strongest entity.
	type pair struct{ u, v int }
	at := map[pair]int{}
	var ge []cohesion.Edge
	var kept []link
	for _, e := range b.edges {
		p := pair{b.local[e.a], b.local[e.b]}
		if p.u > p.v {
			p.u, p.v = p.v, p.u
		}
		w := idx.Weight[e.key]
		if i, ok := at[p]; ok {
			if w > ge[i].Weight || (w == ge[i].Weight && e.key < ge[i].Key) {
				ge[i].Weight, ge[i].Key = w, e.key
				kept[i] = e
			}
			if e.laundered {
				kept[i].laundered = true
			}
			continue
		}
		at[p] = len(ge)
		ge = append(ge, cohesion.Edge{U: p.u, V: p.v, Weight: w, Key: e.key})
		kept = append(kept, e)
	}
	b.edges = kept
	b.graph = cohesion.NewGraph(len(b.nodes), ge)
	grade, bridges := cohesion.Grade(b.graph, cohesion.Bridges(b.graph))
	recurring := false
	if grade == cohesion.Fragile {
		// A weak bridge only suggests a wrong merge when the two halves look
		// different. A periodic job split by time is one activity whose
		// halves share almost every entity; two incidents joined through a
		// busy server share little beyond it.
		pick := -1
		for i, br := range bridges {
			if b.graph.Edges[br.Edge].Weight >= cohesion.FragileWeight {
				break
			}
			if bridgeSimilarity(b, nodes, idx, br) < SameActivityJaccard {
				pick = i
				break
			}
		}
		if pick < 0 {
			grade, recurring = cohesion.Moderate, true
		} else if pick > 0 {
			bridges = append([]cohesion.Bridge{bridges[pick]}, append(bridges[:pick:pick], bridges[pick+1:]...)...)
		}
	}
	b.grade, b.bridges = grade, bridges
	switch grade {
	case cohesion.Fragile:
		br := bridges[0]
		e := ge[br.Edge]
		pct := 100 * float64(idx.DF[e.Key]) / float64(max(idx.N, 1))
		b.reason = fmt.Sprintf("one link through %s (in %.1f%% of alerts) holds together two parts of %d and %d alerts",
			e.Key, pct, br.ChildSide, br.OtherSide)
	case cohesion.Moderate:
		if recurring {
			b.reason = "weak single links join parts that look alike: one recurring activity split by time"
		} else {
			b.reason = fmt.Sprintf("%d single link(s) hold it together, each through a rare entity", len(bridges))
		}
	default:
		if len(b.nodes) < 2*cohesion.MinHalf {
			b.reason = "too small to split into two substantial parts"
		} else {
			b.reason = "no single link holds it together"
		}
	}
}

// preview estimates the two incidents a split along the weakest bridge would
// produce, scored against this run's bands.
func (b *build) preview(nodes []node, base risk.Context, bands domain.Bands, t Techniques) {
	br := b.bridges[0]
	e := b.graph.Edges[br.Edge]
	side := cohesion.Side(b.graph, e.U, br.Edge)
	var left, right []int
	for i, n := range b.nodes {
		if side[i] {
			left = append(left, n)
		} else {
			right = append(right, n)
		}
	}
	if left[0] > right[0] {
		left, right = right, left
	}
	half := func(ns []int) domain.SplitHalf {
		in := map[int]bool{}
		for _, n := range ns {
			in[n] = true
		}
		ctx := base
		for i, l := range b.edges {
			if i != br.Edge && l.laundered && in[l.a] && in[l.b] {
				ctx.Laundered = true
			}
		}
		res := risk.Evaluate(members2(nodes, ns), ctx)
		ids := make([]string, len(ns))
		for i, n := range ns {
			ids[i] = nodes[n].a.ID
		}
		return domain.SplitHalf{
			AlertIDs: ids, Alerts: len(ns), MaxStage: res.MaxStage,
			Headline:    headline(nodes, ns, res, "single"),
			EstRisk:     res.Risk,
			EstPriority: risk.Priority(res, bands),
		}
	}
	b.previewV = &domain.SplitPreview{Left: half(left), Right: half(right)}
}

func (b *build) incident(nodes []node, idx *entity.Index, t Techniques, cfg Config) domain.Incident {
	inc := domain.Incident{
		ID: b.id, Rank: b.rank, Label: b.label, Priority: b.priority,
		Risk: b.res.Risk, Confidence: b.res.Q, Cohesion: b.grade, CohesionReason: b.reason,
		MaxStage: b.res.MaxStage, ForwardStages: b.res.ForwardStages,
		FirstSeen: nodes[b.nodes[0]].a.TS, LastSeen: nodes[b.nodes[len(b.nodes)-1]].a.TS,
		Assets: b.res.Hosts, LaunderingInferred: b.laundered, Breach: b.breach,
		SplitPreview: b.previewV, Sources: map[string]int{},
	}
	if inc.Assets == nil {
		inc.Assets = []string{}
	}
	stageSet := map[int]bool{}
	for _, n := range b.nodes {
		nd := nodes[n]
		inc.AlertIDs = append(inc.AlertIDs, nd.a.ID)
		inc.Sources[nd.a.Source]++
		if nd.stage >= 0 {
			stageSet[nd.stage] = true
		}
	}
	for s := range stageSet {
		inc.Stages = append(inc.Stages, s)
	}
	sort.Ints(inc.Stages)
	if inc.Stages == nil {
		inc.Stages = []int{}
	}
	onChain := map[int]int{} // run node → order (1-based)
	for i, c := range b.res.Chain {
		n := b.nodes[c]
		onChain[n] = i + 1
		inc.ChainIDs = append(inc.ChainIDs, nodes[n].a.ID)
	}
	if inc.ChainIDs == nil {
		inc.ChainIDs = []string{}
	}
	inc.Headline = headline(nodes, b.nodes, b.res, b.label)

	overrides := []string{}
	if b.res.Override != "" {
		overrides = append(overrides, b.res.Override)
	}
	if b.laundered {
		overrides = append(overrides, fmt.Sprintf("confidence ×%.2f: part of this chain was linked through a stop-listed entity", risk.LaunderingPenalty))
	}
	topAssets := b.res.TopAssets
	if topAssets == nil {
		topAssets = []domain.BreakdownAsset{}
	}
	inc.Breakdown = domain.Breakdown{
		C: b.res.C, S: b.res.S, A: b.res.A, Q: b.res.Q, Weights: cfg.Weights, Risk: b.res.Risk,
		ForwardStages: b.res.ForwardStages, Overrides: overrides, TopAssets: topAssets, Rules: b.res.Rules,
	}

	// entities
	launderKeys := map[string]bool{}
	for _, e := range b.edges {
		if e.laundered {
			launderKeys[e.key] = true
		}
	}
	entCount := map[string]int{}
	for _, n := range b.nodes {
		for _, k := range nodes[n].keys {
			if !idx.Stoplist[k] || launderKeys[k] {
				entCount[k]++
			}
		}
	}
	for k, c := range entCount {
		inc.Entities = append(inc.Entities, domain.IncidentEntity{Key: k, Weight: round2(idx.Weight[k]), Alerts: c})
	}
	sort.Slice(inc.Entities, func(i, j int) bool {
		a, c := inc.Entities[i], inc.Entities[j]
		if a.Alerts != c.Alerts {
			return a.Alerts > c.Alerts
		}
		if a.Weight != c.Weight {
			return a.Weight > c.Weight
		}
		return a.Key < c.Key
	})
	if len(inc.Entities) > maxEntitiesListed {
		inc.Entities = inc.Entities[:maxEntitiesListed]
	}
	if inc.Entities == nil {
		inc.Entities = []domain.IncidentEntity{}
	}

	// techniques
	tech := map[string]*domain.IncidentTechnique{}
	for _, n := range b.nodes {
		nd := nodes[n]
		if nd.a.TechniqueID == "" {
			continue
		}
		x, ok := tech[nd.a.TechniqueID]
		if !ok {
			x = &domain.IncidentTechnique{TechniqueID: nd.a.TechniqueID, Name: nd.tname, Tactic: nd.tactic, Stage: max(nd.stage, 0)}
			tech[nd.a.TechniqueID] = x
		}
		x.Alerts++
	}
	for _, x := range tech {
		inc.Techniques = append(inc.Techniques, *x)
	}
	sort.Slice(inc.Techniques, func(i, j int) bool {
		if inc.Techniques[i].Stage != inc.Techniques[j].Stage {
			return inc.Techniques[i].Stage < inc.Techniques[j].Stage
		}
		return inc.Techniques[i].TechniqueID < inc.Techniques[j].TechniqueID
	})
	if inc.Techniques == nil {
		inc.Techniques = []domain.IncidentTechnique{}
	}

	// bridges
	inc.BridgeEdges = []domain.BridgeEdge{}
	bridgeAlerts := map[string]string{} // later alert of a bridge → entity key
	for i, br := range b.bridges {
		if i == maxBridgesReported {
			break
		}
		ge := b.graph.Edges[br.Edge]
		l := b.edges[br.Edge]
		left, right := br.OtherSide, br.ChildSide
		if br.Child == ge.U {
			left, right = br.ChildSide, br.OtherSide
		}
		inc.BridgeEdges = append(inc.BridgeEdges, domain.BridgeEdge{
			AlertA: nodes[l.a].a.ID, AlertB: nodes[l.b].a.ID, EntityKey: l.key,
			Weight: round2(ge.Weight), LeftSize: left, RightSize: right,
		})
		bridgeAlerts[nodes[l.b].a.ID] = l.key
	}

	inc.Graph = graph(nodes, b.nodes, onChain, idx, launderKeys, bridgeAlerts, t)
	inc.Timeline = timeline(nodes, b.nodes, onChain, inc.ChainIDs, t)
	return inc
}

// ---------- headline ----------

var phrases = map[string]string{
	"T1110": "brute force", "T1110.001": "brute force", "T1110.003": "password spray",
	"T1078": "valid-account login", "T1078.002": "privileged login", "T1078.004": "cloud account login",
	"T1566": "phishing", "T1566.001": "phishing attachment", "T1566.002": "phishing link",
	"T1204": "user execution", "T1204.002": "malicious file opened",
	"T1059": "script execution", "T1059.001": "PowerShell execution",
	"T1053": "scheduled task", "T1053.005": "scheduled task", "T1543": "new service", "T1543.003": "new service",
	"T1003": "credential dumping", "T1003.001": "LSASS dump",
	"T1621": "MFA fatigue", "T1528": "token theft", "T1564.008": "inbox rule",
	"T1685": "security tools disabled", "T1685.005": "event logs cleared",
	"T1046": "port scan", "T1087": "account discovery", "T1087.002": "domain account discovery", "T1018": "host discovery",
	"T1021": "lateral movement", "T1021.001": "lateral movement", "T1021.002": "lateral movement", "T1570": "tool transfer",
	"T1071": "C2 beacon", "T1071.001": "C2 beacon", "T1071.004": "DNS tunnelling", "T1090": "proxy C2", "T1090.003": "proxy C2",
	"T1105": "tool download", "T1560": "data staging", "T1560.001": "data staging",
	"T1530": "cloud data access", "T1114": "mailbox collection", "T1114.002": "mailbox collection",
	"T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration", "T1567.002": "exfiltration to cloud storage",
	"T1486": "encryption", "T1490": "backup deletion",
}

func phrase(nd node) string {
	p, ok := phrases[nd.a.TechniqueID]
	if !ok {
		if i := strings.IndexByte(nd.a.TechniqueID, '.'); i > 0 {
			p, ok = phrases[nd.a.TechniqueID[:i]]
		}
	}
	if !ok {
		if nd.tname != "" {
			p = strings.ToLower(nd.tname)
		} else {
			p = strings.ToLower(nd.a.RuleName)
		}
	}
	switch strings.ToLower(nd.tactic) {
	case "lateral movement":
		if len(nd.hosts) > 0 {
			p += " to " + nd.hosts[len(nd.hosts)-1]
		}
	case "exfiltration", "collection":
		if len(nd.hosts) > 0 {
			p += " from " + nd.hosts[0]
		}
	case "impact":
		if len(nd.hosts) > 0 {
			p += " on " + nd.hosts[0]
		}
	}
	return p
}

func headline(nodes []node, ns []int, res risk.Result, lbl string) string {
	if len(res.Chain) >= 2 {
		var parts []string
		for _, c := range res.Chain {
			p := phrase(nodes[ns[c]])
			if len(parts) == 0 || parts[len(parts)-1] != p {
				parts = append(parts, p)
			}
		}
		if len(parts) > maxHeadlineSteps {
			parts = append(parts[:2], parts[len(parts)-(maxHeadlineSteps-2):]...)
		}
		return sentence(strings.Join(parts, " → "))
	}
	first := nodes[ns[0]]
	subject := ""
	switch {
	case len(first.hosts) > 0:
		subject = first.hosts[0]
	case len(first.a.Entities.Users) > 0:
		subject = first.a.Entities.Users[0]
	case len(first.a.Entities.IPs) > 0:
		subject = first.a.Entities.IPs[0]
	}
	if lbl == "noise_cluster" || len(ns) > 1 {
		h := fmt.Sprintf("%s ×%d", first.a.RuleName, len(ns))
		if subject != "" {
			h += " on " + subject
		}
		return h
	}
	if subject != "" {
		return first.a.RuleName + " on " + subject
	}
	return first.a.RuleName
}

// ---------- projections ----------

func graph(nodes []node, ns []int, onChain map[int]int, idx *entity.Index, launderKeys map[string]bool, bridgeAlerts map[string]string, t Techniques) domain.Graph {
	type pair struct{ s, t string }
	type cand struct {
		e    domain.GraphEdge
		prio int
	}
	best := map[pair]*cand{}
	var order []pair
	used := map[string]bool{}
	for _, n := range ns {
		nd := nodes[n]
		keep := func(k string) bool { return !idx.Stoplist[k] || launderKeys[k] }
		var actors, extras []string
		for _, k := range nd.keys {
			if !keep(k) {
				continue
			}
			switch entity.Type(k) {
			case "user":
				actors = append(actors, k)
			case "ip":
				if entity.IsExternal(entity.Value(k)) {
					actors = append(actors, k)
				} else {
					extras = append(extras, k)
				}
			case "host":
				// placed on the spine below, in the alert's own order
			default:
				extras = append(extras, k)
			}
		}
		// keep the alert's own host order (source → destination)
		hosts := orderedHosts(nd, keep) // source → destination
		spine := append(append([]string{}, actors...), hosts...)
		var pairs []pair
		for i := 1; i < len(spine); i++ {
			pairs = append(pairs, pair{spine[i-1], spine[i]})
		}
		hub := ""
		if len(hosts) > 0 {
			hub = hosts[0]
		} else if len(spine) > 0 {
			hub = spine[len(spine)-1]
		}
		for _, x := range extras {
			if hub == "" {
				hub = x
				continue
			}
			pairs = append(pairs, pair{hub, x})
		}
		if len(spine) == 1 && len(extras) == 0 {
			used[spine[0]] = true
		}
		var tid *string
		if nd.a.TechniqueID != "" {
			v := nd.a.TechniqueID
			tid = &v
		}
		bkey, isBridgeAlert := bridgeAlerts[nd.a.ID]
		for _, p := range pairs {
			if p.s == p.t {
				continue
			}
			e := domain.GraphEdge{Source: p.s, Target: p.t, AlertID: nd.a.ID, TS: nd.a.TS,
				Stage: max(nd.stage, 0), TechniqueID: tid, OnChain: onChain[n] > 0, Order: onChain[n],
				IsBridge: isBridgeAlert && (p.s == bkey || p.t == bkey)}
			prio := 0
			if e.IsBridge {
				prio += 2
			}
			if e.OnChain {
				prio++
			}
			if c, ok := best[p]; ok {
				if prio > c.prio {
					c.e, c.prio = e, prio
				}
				continue
			}
			best[p] = &cand{e, prio}
			order = append(order, p)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return best[order[i]].prio > best[order[j]].prio })
	if len(order) > maxGraphEdges {
		order = order[:maxGraphEdges]
	}
	g := domain.Graph{Nodes: []domain.GraphNode{}, Edges: []domain.GraphEdge{}}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := best[order[i]].e, best[order[j]].e
		if !a.TS.Equal(b.TS) {
			return a.TS.Before(b.TS)
		}
		if a.AlertID != b.AlertID {
			return a.AlertID < b.AlertID
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Target < b.Target
	})
	for i, p := range order {
		e := best[p].e
		e.ID = fmt.Sprintf("e%d", i+1)
		g.Edges = append(g.Edges, e)
		used[e.Source], used[e.Target] = true, true
	}
	keys := make([]string, 0, len(used))
	for k := range used {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		typ, val := entity.Type(k), entity.Value(k)
		gn := domain.GraphNode{ID: k, Type: typ, Label: val, DataClasses: []string{}, Stoplisted: idx.Stoplist[k]}
		switch typ {
		case "host":
			gn.Label = strings.ToUpper(val)
		case "ip":
			gn.External = entity.IsExternal(val)
		}
		g.Nodes = append(g.Nodes, gn)
	}
	return g
}

func orderedHosts(nd node, keep func(string) bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range nd.hosts {
		k := "host:" + h
		if keep(k) && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

func timeline(nodes []node, ns []int, onChain map[int]int, chain []string, t Techniques) domain.Timeline {
	tl := domain.Timeline{Chain: chain, Points: make([]domain.TimelinePoint, 0, len(ns))}
	for s := 0; s < 7; s++ {
		var tactics []string
		if t != nil {
			tactics = t.TacticsForStage(s)
		}
		if tactics == nil {
			tactics = []string{}
		}
		tl.Lanes = append(tl.Lanes, domain.TimelineLane{Stage: s, Name: attack.StageNames[s], Tactics: tactics})
	}
	for _, n := range ns {
		nd := nodes[n]
		tl.Points = append(tl.Points, domain.TimelinePoint{AlertID: nd.a.ID, TS: nd.a.TS, Stage: max(nd.stage, 0),
			Severity: nd.a.Severity, RuleName: nd.a.RuleName, OnChain: onChain[n] > 0})
	}
	return tl
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

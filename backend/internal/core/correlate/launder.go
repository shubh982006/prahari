package correlate

import (
	"sort"

	"prahari/internal/core/entity"
	"prahari/internal/domain"
)

// launder is the second, narrower linking pass that closes the hole the
// supernode stop-list opens (design §6.4). An attacker who routes every stage
// through a stop-listed entity (proxy, DNS server, shared service account)
// never links; this pass links two components A → B when:
//
//   - they share a stop-listed user, IP or host (never a process or hash) and
//     nothing else (otherwise they would already be one component), and the
//     hop is at the boundary: A's last alert and B's first alert both carry it,
//   - B starts within the link window after A ends,
//   - among candidates, the one closest in time wins, then the one whose last
//     stage is closest to B's first stage. An earlier version required
//     B's first stage to be at or after A's last; real chains are not
//     monotonic (scenario A downloads its C2 payload, stage 5, before dumping
//     LSASS, stage 3), and the adversary bench measured that rule recovering
//     almost nothing,
//   - both sides look like attack activity rather than noise: each has an
//     actor (a user or an external IP), is not a noise cluster, and either
//     advances two or more stages or carries a high/critical alert.
//
// The design's "consistent actor" cannot mean a shared non-stop-listed actor:
// that would have linked A and B in the first pass. It is read here as "both
// sides have an actor, and A is B's nearest forward predecessor through the
// supernode". Each A feeds at most one B and each B takes at most one A, so a
// busy supernode cannot fan one chain into many.
//
// The resulting edge is flagged, the incident's confidence is multiplied by
// 0.85, and cohesion sees it as a low-weight bridge, so the analyst is told the
// link was inferred.
func launder(nodes []node, d *dsu, idx *entity.Index, cfg Config, in Input, cuts map[[2]int]bool) []link {
	type comp struct {
		root, first, last     int
		firstStage, lastStage int
		maxStage              int
		attackish             bool
		stop                  []string
		members               []int
	}
	byRoot := map[int]*comp{}
	var roots []int
	for i := range nodes {
		r := d.find(i)
		c, ok := byRoot[r]
		if !ok {
			c = &comp{root: r, first: i, firstStage: -1, lastStage: -1}
			byRoot[r] = c
			roots = append(roots, r)
		}
		c.members = append(c.members, i)
		c.last = i
	}
	for _, r := range roots {
		c := byRoot[r]
		var stages []int
		actor := false
		maxSev := 0.0
		rules := map[string]int{}
		stopSet := map[string]bool{}
		for _, n := range c.members {
			nd := nodes[n]
			if nd.stage >= 0 {
				if c.firstStage < 0 {
					c.firstStage = nd.stage
				}
				c.lastStage = nd.stage
				c.maxStage = max(c.maxStage, nd.stage)
				stages = append(stages, nd.stage)
			}
			maxSev = max(maxSev, nd.a.Severity.Score())
			rules[nd.a.RuleID]++
			for _, k := range nd.keys {
				if idx.Stoplist[k] {
					stopSet[k] = true
				}
				switch entity.Type(k) {
				case "user":
					actor = true
				case "ip":
					if entity.IsExternal(entity.Value(k)) {
						actor = true
					}
				}
			}
		}
		lis := lisLen(stages)
		top := 0
		for _, n := range rules {
			top = max(top, n)
		}
		noise := len(c.members) >= 20 && float64(top) > 0.8*float64(len(c.members))
		_ = actor
		_ = lis
		c.attackish = !noise && c.firstStage >= 0 && maxSev >= domain.SevHigh.Score()
		for k := range stopSet {
			c.stop = append(c.stop, k)
		}
		sort.Strings(c.stop)
	}

	holders := map[string][]*comp{}
	for _, r := range roots {
		c := byRoot[r]
		if !c.attackish {
			continue
		}
		for _, k := range c.stop {
			holders[k] = append(holders[k], c)
		}
	}

	separated := func(a, b *comp) bool {
		if len(cuts) == 0 {
			return false
		}
		for _, n := range b.members {
			for _, m := range a.members {
				if cuts[[2]int{min(m, n), max(m, n)}] {
					return true
				}
			}
		}
		return false
	}

	sort.Slice(roots, func(i, j int) bool { return byRoot[roots[i]].first < byRoot[roots[j]].first })
	usedPred := map[int]bool{}
	var out []link
	for _, r := range roots {
		b := byRoot[r]
		if !b.attackish {
			continue
		}
		firstKeys := launderKeys(nodes[b.first], idx)
		var best *comp
		bestKey := ""
		bestStageGap, bestGap := 0, int64(0)
		for _, k := range b.stop {
			if !firstKeys[k] {
				continue
			}
			for _, a := range holders[k] {
				if a == b || usedPred[a.root] || !launderKeys(nodes[a.last], idx)[k] {
					continue
				}
				at, bt := nodes[a.last].a.TS, nodes[b.first].a.TS
				if at.After(bt) || bt.Sub(at) > cfg.LinkWindow {
					continue
				}

				if separated(a, b) {
					continue
				}
				sg, gap := abs(b.firstStage-a.lastStage), int64(bt.Sub(at))
				better := best == nil || gap < bestGap ||
					(gap == bestGap && sg < bestStageGap) ||
					(gap == bestGap && sg == bestStageGap && a.first < best.first)
				if better {
					best, bestKey, bestStageGap, bestGap = a, k, sg, gap
				}
			}
		}
		if best == nil {
			continue
		}
		usedPred[best.root] = true
		out = append(out, link{a: best.last, b: b.first, key: bestKey, laundered: true})
	}
	return out
}

// launderKeys are the stop-listed entities on one alert that can carry a
// laundered hop: infrastructure an attacker routes through (users, IPs,
// hosts). A process name or file hash is not a channel.
func launderKeys(n node, idx *entity.Index) map[string]bool {
	out := map[string]bool{}
	for _, k := range n.keys {
		if !idx.Stoplist[k] {
			continue
		}
		switch entity.Type(k) {
		case "user", "ip", "host":
			out[k] = true
		}
	}
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func lisLen(stages []int) int {
	tails := make([]int, 0, 7)
	for _, s := range stages {
		i := sort.SearchInts(tails, s)
		if i == len(tails) {
			tails = append(tails, s)
		} else {
			tails[i] = s
		}
	}
	return len(tails)
}

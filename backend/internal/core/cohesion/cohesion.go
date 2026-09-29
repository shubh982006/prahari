// Package cohesion reports how sure the engine is that an incident is one
// thing. An incident is a connected component of the alert-link graph; an edge
// whose removal splits it is a bridge (Tarjan, O(V+E)). A bridge on a rare
// entity is fine: every edge of a genuine path-shaped chain is a bridge. A
// bridge on a common entity that splits the incident into two substantial
// halves means it is probably two incidents.
package cohesion

import (
	"math"
	"sort"
)

const (
	Solid    = "solid"
	Moderate = "moderate"
	Fragile  = "fragile"
)

// FragileWeight is ln(N / 0.02N): an entity seen in more than 2% of the day's
// alerts is weak evidence for a merge.
var FragileWeight = math.Log(50)

// MinHalf is the smallest side that counts as "substantial".
const MinHalf = 3

type Edge struct {
	U, V   int // node indices
	Weight float64
	Key    string
}

type Graph struct {
	N     int
	Edges []Edge
	adj   [][]half
}

type half struct{ to, edge int }

func NewGraph(n int, edges []Edge) *Graph {
	g := &Graph{N: n, Edges: edges, adj: make([][]half, n)}
	for i, e := range edges {
		g.adj[e.U] = append(g.adj[e.U], half{e.V, i})
		g.adj[e.V] = append(g.adj[e.V], half{e.U, i})
	}
	return g
}

// Bridge is one bridge edge and the sizes of the two sides it separates.
// Child is the node on the DFS-subtree side.
type Bridge struct {
	Edge      int
	Child     int
	ChildSide int
	OtherSide int
}

func (b Bridge) Minor() int { return min(b.ChildSide, b.OtherSide) }

// Bridges finds all bridges with Tarjan's low-link DFS. Parallel edges (two
// alerts sharing two entities) are correctly never bridges because only the
// exact parent edge is skipped, not the parent node. The DFS is iterative so a
// very large component cannot exhaust the stack.
func Bridges(g *Graph) []Bridge {
	disc := make([]int, g.N)
	low := make([]int, g.N)
	size := make([]int, g.N)
	for i := range disc {
		disc[i] = -1
	}
	type frame struct{ node, parentEdge, next int }
	var out []Bridge
	timer := 0
	for root := 0; root < g.N; root++ {
		if disc[root] != -1 {
			continue
		}
		compSize := 0
		var found []Bridge
		stack := []frame{{root, -1, 0}}
		disc[root], low[root], size[root] = timer, timer, 1
		timer++
		for len(stack) > 0 {
			f := &stack[len(stack)-1]
			u := f.node
			if f.next < len(g.adj[u]) {
				h := g.adj[u][f.next]
				f.next++
				if h.edge == f.parentEdge {
					continue
				}
				if disc[h.to] == -1 {
					disc[h.to], low[h.to], size[h.to] = timer, timer, 1
					timer++
					stack = append(stack, frame{h.to, h.edge, 0})
				} else {
					low[u] = min(low[u], disc[h.to])
				}
				continue
			}
			stack = stack[:len(stack)-1]
			compSize++
			if len(stack) > 0 {
				p := stack[len(stack)-1].node
				low[p] = min(low[p], low[u])
				size[p] += size[u]
				if low[u] > disc[p] {
					found = append(found, Bridge{Edge: f.parentEdge, Child: u, ChildSide: size[u]})
				}
			}
		}
		for i := range found {
			found[i].OtherSide = compSize - found[i].ChildSide
		}
		out = append(out, found...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Edge < out[j].Edge })
	return out
}

// Grade classifies a component and returns the bridges worth reporting
// (those with a substantial minor side), weakest first. The first returned
// bridge is the one a split would cut when the grade is fragile.
func Grade(g *Graph, bridges []Bridge) (string, []Bridge) {
	var substantial []Bridge
	for _, b := range bridges {
		if b.Minor() >= MinHalf {
			substantial = append(substantial, b)
		}
	}
	sort.SliceStable(substantial, func(i, j int) bool {
		wi, wj := g.Edges[substantial[i].Edge].Weight, g.Edges[substantial[j].Edge].Weight
		if wi != wj {
			return wi < wj
		}
		if substantial[i].Minor() != substantial[j].Minor() {
			return substantial[i].Minor() > substantial[j].Minor()
		}
		return substantial[i].Edge < substantial[j].Edge
	})
	if len(substantial) == 0 {
		return Solid, nil
	}
	if g.Edges[substantial[0].Edge].Weight < FragileWeight {
		return Fragile, substantial
	}
	return Moderate, substantial
}

// Side returns the node set reachable from start without crossing edge cut.
func Side(g *Graph, start, cut int) []bool {
	in := make([]bool, g.N)
	in[start] = true
	q := []int{start}
	for len(q) > 0 {
		u := q[0]
		q = q[1:]
		for _, h := range g.adj[u] {
			if h.edge == cut || in[h.to] {
				continue
			}
			in[h.to] = true
			q = append(q, h.to)
		}
	}
	return in
}

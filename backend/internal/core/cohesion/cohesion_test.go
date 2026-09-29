package cohesion

import "testing"

func path(n int, w float64) *Graph {
	var es []Edge
	for i := 1; i < n; i++ {
		es = append(es, Edge{U: i - 1, V: i, Weight: w, Key: "k"})
	}
	return NewGraph(n, es)
}

func TestEveryEdgeOfAPathIsABridge(t *testing.T) {
	g := path(6, 5)
	bs := Bridges(g)
	if len(bs) != 5 {
		t.Fatalf("path of 6 has 5 bridges, got %d", len(bs))
	}
	for _, b := range bs {
		if b.ChildSide+b.OtherSide != 6 {
			t.Fatalf("sides must sum to the component: %+v", b)
		}
	}
}

func TestCycleHasNoBridges(t *testing.T) {
	g := NewGraph(4, []Edge{{U: 0, V: 1}, {U: 1, V: 2}, {U: 2, V: 3}, {U: 3, V: 0}})
	if bs := Bridges(g); len(bs) != 0 {
		t.Fatalf("cycle: %+v", bs)
	}
}

func TestParallelEdgesAreNotBridges(t *testing.T) {
	g := NewGraph(2, []Edge{{U: 0, V: 1, Key: "host"}, {U: 0, V: 1, Key: "ip"}})
	if bs := Bridges(g); len(bs) != 0 {
		t.Fatalf("two links between the same alerts are not a bridge: %+v", bs)
	}
}

func TestTwoTrianglesJoinedByOneEdge(t *testing.T) {
	es := []Edge{
		{U: 0, V: 1, Weight: 6}, {U: 1, V: 2, Weight: 6}, {U: 2, V: 0, Weight: 6},
		{U: 3, V: 4, Weight: 6}, {U: 4, V: 5, Weight: 6}, {U: 5, V: 3, Weight: 6},
		{U: 2, V: 3, Weight: 3.1, Key: "ip:10.1.0.53"},
	}
	g := NewGraph(6, es)
	bs := Bridges(g)
	if len(bs) != 1 || bs[0].Edge != 6 || bs[0].Minor() != 3 {
		t.Fatalf("want the single joining edge with halves of 3: %+v", bs)
	}
	grade, ranked := Grade(g, bs)
	if grade != Fragile || ranked[0].Edge != 6 {
		t.Fatalf("a weak bridge between two substantial halves is fragile, got %s", grade)
	}
	es[6].Weight = 6
	g = NewGraph(6, es)
	if grade, _ := Grade(g, Bridges(g)); grade != Moderate {
		t.Fatalf("the same bridge on a rare entity is moderate, got %s", grade)
	}
}

func TestSmallSidesAreSolid(t *testing.T) {
	g := path(4, 1) // halves of at most 2
	if grade, _ := Grade(g, Bridges(g)); grade != Solid {
		t.Fatalf("got %s", grade)
	}
}

func TestDeepComponentDoesNotOverflow(t *testing.T) {
	if n := len(Bridges(path(200_000, 5))); n != 199_999 {
		t.Fatalf("got %d bridges", n)
	}
}

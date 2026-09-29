package compliance

import (
	"testing"

	"prahari/internal/domain"
)

func TestTrigger(t *testing.T) {
	assets := map[string]domain.Asset{
		"fin-db-01": {Hostname: "fin-db-01", Criticality: 9, DataClasses: []string{"pii", "financial"}},
		"build01":   {Hostname: "build01", Criticality: 6, DataClasses: []string{"source_code"}},
	}
	cases := []struct {
		pri   string
		stage int
		hosts []string
		want  bool
	}{
		{"P1", 6, []string{"fin-db-01"}, true},
		{"P2", 5, []string{"fin-db-01"}, true},
		{"P3", 6, []string{"fin-db-01"}, false}, // not urgent enough
		{"P1", 4, []string{"fin-db-01"}, false}, // no collection or exfiltration yet
		{"P1", 6, []string{"build01"}, false},   // source code is not personal or financial data
	}
	for _, c := range cases {
		if got := Trigger(c.pri, c.stage, c.hosts, assets) != nil; got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestThreeTracks(t *testing.T) {
	if len(Tracks) != 3 {
		t.Fatal("CERT-In 6 h, DPDP intimation 1 h, DPDP report 72 h")
	}
	for name, hours := range map[string]float64{"certin": 6, "dpdp_intimation": 1, "dpdp_report": 72} {
		tr, ok := TrackByName(name)
		if !ok || tr.Offset.Hours() != hours {
			t.Errorf("%s: %+v", name, tr)
		}
	}
}

package attack

import (
	"strings"
	"testing"
)

func TestPinnedBundle(t *testing.T) {
	c, err := LoadFile("../../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "19.0" || c.Len() < 600 {
		t.Fatalf("version %s, %d techniques", c.Version, c.Len())
	}
	for id, stage := range map[string]int{"T1110.003": 3, "T1078": 1, "T1021.001": 4, "T1041": 6, "T1685": 3, "T1566.001": 1, "T1560.001": 5} {
		if s, ok := c.StageOf(id); !ok || s != stage {
			t.Errorf("%s: stage %d (%v), want %d", id, s, ok, stage)
		}
	}
	// v19 split Defense Evasion: both halves land in stage 3
	got := strings.Join(c.TacticsForStage(3), ",")
	if !strings.Contains(got, "Stealth") || !strings.Contains(got, "Defense Impairment") {
		t.Fatalf("stage 3 tactics: %s", got)
	}
	if _, ok := c.StageOf("T1562.001"); ok {
		t.Fatal("T1562.001 was revoked in v19 and must not resolve")
	}
}

func TestUnknownTacticFailsLoudly(t *testing.T) {
	b := `{"objects":[{"type":"x-mitre-tactic","name":"Time Travel","x_mitre_shortname":"time-travel"}]}`
	if _, err := Load(strings.NewReader(b)); err == nil || !strings.Contains(err.Error(), "no kill-chain stage") {
		t.Fatalf("a tactic with no stage must fail the load, got %v", err)
	}
}

package receipt

import (
	"testing"
	"time"

	"prahari/internal/domain"
)

func TestConfigHashIgnoresMapOrder(t *testing.T) {
	a := map[string]any{"b": 1, "a": map[string]any{"z": 1, "y": 2}}
	b := map[string]any{"a": map[string]any{"y": 2, "z": 1}, "b": 1}
	for i := 0; i < 50; i++ { // map iteration is randomised; hash many times
		if ConfigHash(a) != ConfigHash(b) {
			t.Fatal("map order leaked into the hash")
		}
	}
}

func TestInputHashIsOrderIndependentButContentSensitive(t *testing.T) {
	t0 := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	x := domain.Alert{ID: "A", TS: t0, RuleID: "R", Severity: "low", Entities: domain.Entities{Users: []string{"u"}}}
	y := domain.Alert{ID: "B", TS: t0.Add(time.Second), RuleID: "R", Severity: "low"}
	if InputHash([]domain.Alert{x, y}) != InputHash([]domain.Alert{y, x}) {
		t.Fatal("input order changed the hash")
	}
	z := x
	z.Severity = "high"
	if InputHash([]domain.Alert{x, y}) == InputHash([]domain.Alert{z, y}) {
		t.Fatal("a content change did not change the hash")
	}
}

func TestOutputHashUsesTwoDecimalRisk(t *testing.T) {
	a := []domain.Incident{{ID: "INC-1", Priority: "P1", Risk: 98.92, Cohesion: "solid", AlertIDs: []string{"b", "a"}}}
	b := []domain.Incident{{ID: "INC-1", Priority: "P1", Risk: 98.920000000001, Cohesion: "solid", AlertIDs: []string{"a", "b"}}}
	if OutputHash(a) != OutputHash(b) {
		t.Fatal("float noise below 2 dp or member order changed the hash")
	}
}

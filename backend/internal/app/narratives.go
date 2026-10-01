package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"prahari/internal/core/narrate"
	"prahari/internal/domain"
)

const (
	breakerThreshold = 5
	breakerCooldown  = time.Minute
	llmTimeout       = 20 * time.Second
)

// breaker opens after consecutive LLM failures so a dead endpoint costs one
// fast fallback per request instead of a 20-second timeout.
type breaker struct {
	mu       sync.Mutex
	failures int
	openTill time.Time
}

func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.After(b.openTill)
}

func (b *breaker) record(ok bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= breakerThreshold {
		b.openTill = now.Add(breakerCooldown)
		b.failures = 0
	}
}

type NarrativeView struct {
	IncidentID         string          `json:"incident_id"`
	FactsHash          string          `json:"facts_hash"`
	Source             string          `json:"source"`
	Model              *string         `json:"model"`
	Attempts           int             `json:"attempts"`
	Headline           string          `json:"headline"`
	Sentences          []narrate.Cited `json:"sentences"`
	RecommendedActions []narrate.Cited `json:"recommended_actions"`
	Validation         Validation      `json:"validation"`
	GeneratedAt        time.Time       `json:"generated_at"`
}

type Validation struct {
	Passed bool     `json:"passed"`
	Issues []string `json:"issues"`
}

type narrateJob struct{ runID, incidentID string }

func (a *App) narrateWorker(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		case j := <-a.narrateQueue:
			if _, err := a.Narrative(ctx, j.runID, j.incidentID, false); err != nil {
				a.Log.Debug("prewarm narrative", "incident_id", j.incidentID, "err", err)
			}
		}
	}
}

// prewarm queues narratives for the top of a fresh queue so no live model
// call sits on the demo path.
func (a *App) prewarm(runID string, incs []domain.Incident) {
	for i, inc := range incs {
		if i == 40 {
			return
		}
		select {
		case a.narrateQueue <- narrateJob{runID, inc.ID}:
		default:
			return
		}
	}
}

// Narrative returns the brief for an incident. It never fails because of the
// model: on timeout, open breaker or failed validation it falls back to the
// deterministic template.
func (a *App) Narrative(ctx context.Context, runID, incidentID string, regenerate bool) (NarrativeView, error) {
	row, err := a.Store.GetIncident(ctx, runID, incidentID)
	if err != nil {
		return NarrativeView{}, err
	}
	inc := row.Incident
	ds, err := a.runDataset(ctx, runID)
	if err != nil {
		return NarrativeView{}, err
	}
	alerts, err := a.Store.AlertsByID(ctx, ds, inc.AlertIDs)
	if err != nil {
		return NarrativeView{}, err
	}
	assets, err := a.Store.AssetMap(ctx)
	if err != nil {
		return NarrativeView{}, err
	}
	facts := narrate.BuildFacts(inc, alerts, assets, a.Attack)
	hash := facts.Hash()
	if !regenerate {
		if n, err := a.Store.GetNarrative(ctx, hash); err == nil {
			v := viewOf(n)
			v.Source = "cache"
			return v, nil
		}
	}
	nar, source, model, attempts, issues := a.generate(ctx, facts)
	body, _ := json.Marshal(nar)
	val := Validation{Passed: len(issues) == 0, Issues: nonNil(issues)}
	vb, _ := json.Marshal(val)
	stored := StoredNarrative{FactsHash: hash, IncidentID: incidentID, Source: source, Attempts: attempts, Body: body, Validation: vb, GeneratedAt: a.now()}
	if model != "" {
		stored.Model = &model
	}
	if err := a.Store.PutNarrative(ctx, stored); err != nil {
		a.Log.Warn("cache narrative", "err", err)
	}
	_, _ = a.audit(ctx, a.Store, "system", "narrative.generated", incidentID, map[string]any{"facts_hash": hash, "source": source, "attempts": attempts})
	if regenerate {
		a.notify("narrative.updated", map[string]any{"incident_id": incidentID, "run_id": runID})
	}
	return viewOf(stored), nil
}

func viewOf(n StoredNarrative) NarrativeView {
	var body narrate.Narrative
	_ = json.Unmarshal(n.Body, &body)
	var val Validation
	_ = json.Unmarshal(n.Validation, &val)
	if val.Issues == nil {
		val.Issues = []string{}
	}
	if body.Sentences == nil {
		body.Sentences = []narrate.Cited{}
	}
	if body.RecommendedActions == nil {
		body.RecommendedActions = []narrate.Cited{}
	}
	return NarrativeView{IncidentID: n.IncidentID, FactsHash: n.FactsHash, Source: n.Source, Model: n.Model, Attempts: n.Attempts,
		Headline: body.Headline, Sentences: body.Sentences, RecommendedActions: body.RecommendedActions, Validation: val, GeneratedAt: n.GeneratedAt}
}

// generate tries the model (twice at most, the second attempt told what
// failed validation) and otherwise returns the template.
func (a *App) generate(ctx context.Context, facts narrate.Facts) (narrate.Narrative, string, string, int, []string) {
	tmpl := narrate.Template(facts)
	if !a.LLMEnabled || a.LLM == nil || !a.LLM.Enabled() || !a.breaker.allow(a.now()) {
		return tmpl, "template", "", 0, nil
	}
	var issues []string
	for attempt := 1; attempt <= 2; attempt++ {
		sys, user := narrate.Prompt(facts, issues)
		cctx, cancel := context.WithTimeout(ctx, llmTimeout)
		content, model, err := a.LLM.Complete(cctx, sys, user, narrate.Schema())
		cancel()
		if err != nil {
			a.breaker.record(false, a.now())
			a.Log.Info("llm call failed; using template", "err", err)
			return tmpl, "template", "", attempt, []string{"model unavailable: fell back to template"}
		}
		a.breaker.record(true, a.now())
		var n narrate.Narrative
		if err := json.Unmarshal([]byte(content), &n); err != nil {
			issues = []string{"response was not valid JSON for the schema"}
			continue
		}
		issues = narrate.Validate(n, facts)
		if len(issues) == 0 {
			return n, "llm", model, attempt, nil
		}
	}
	return tmpl, "template", "", 2, append([]string{"model output failed validation twice; template used"}, issues...)
}

func (a *App) runDataset(ctx context.Context, runID string) (string, error) {
	r, err := a.Store.GetRun(ctx, runID)
	if err != nil {
		return "", err
	}
	return r.DatasetID, nil
}

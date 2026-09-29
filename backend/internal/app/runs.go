package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"prahari/internal/core/compliance"
	"prahari/internal/core/correlate"
	"prahari/internal/core/narrate"
	"prahari/internal/core/receipt"
	"prahari/internal/core/risk"
	"prahari/internal/domain"
)

const (
	lockTTL         = 2 * time.Minute
	runTimeout      = 2 * time.Minute
	maintenanceTick = 60 * time.Second
)

// NewID returns a UUIDv7: time-ordered, so run IDs sort by creation.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	ms := uint64(time.Now().UnixMilli())
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Overrides are per-run engine parameter changes for experiments. They are
// validated and snapshotted into the run and its receipt.
type Overrides struct {
	LinkWindow     *string         `json:"link_window,omitempty"`
	SupernodeRatio *float64        `json:"supernode_ratio,omitempty"`
	LaunderingPass *bool           `json:"laundering_pass,omitempty"`
	Weights        *domain.Weights `json:"weights,omitempty"`
	Capacity       *risk.Capacity  `json:"capacity,omitempty"`
}

func (o *Overrides) apply(cfg correlate.Config) (correlate.Config, error) {
	if o == nil {
		return cfg, nil
	}
	var fe []domain.FieldError
	if o.LinkWindow != nil {
		d, err := time.ParseDuration(*o.LinkWindow)
		if err != nil || d < time.Minute || d > 48*time.Hour {
			fe = append(fe, domain.FieldError{Field: "body.overrides.link_window", Message: "must be a duration between 1m and 48h"})
		} else {
			cfg.LinkWindow = d
		}
	}
	if o.SupernodeRatio != nil {
		if *o.SupernodeRatio < 0.001 || *o.SupernodeRatio > 0.5 {
			fe = append(fe, domain.FieldError{Field: "body.overrides.supernode_ratio", Message: "must be between 0.001 and 0.5"})
		} else {
			cfg.SupernodeRatio = *o.SupernodeRatio
		}
	}
	if o.LaunderingPass != nil {
		cfg.LaunderingPass = *o.LaunderingPass
	}
	if w := o.Weights; w != nil {
		sum := w.C + w.S + w.A + w.Q
		if w.C <= 0 || w.S <= 0 || w.A <= 0 || w.Q <= 0 || math.Abs(sum-1) > 0.01 {
			fe = append(fe, domain.FieldError{Field: "body.overrides.weights", Message: "each weight must be positive and they must sum to 1"})
		} else {
			cfg.Weights = *w
		}
	}
	if c := o.Capacity; c != nil {
		if c.P1PerShift < 1 || c.P2PerShift < 1 {
			fe = append(fe, domain.FieldError{Field: "body.overrides.capacity", Message: "p1_per_shift and p2_per_shift must be at least 1"})
		} else {
			cfg.Capacity = *c
		}
	}
	if len(fe) > 0 {
		return cfg, domain.Validation(fe...)
	}
	return cfg, nil
}

type runJob struct {
	runID, datasetID, actor string
	cfg                     correlate.Config
	internal                bool // a campaign or split run, not queued by a user
}

type StageStat struct {
	Stage     string `json:"stage"`
	Count     int    `json:"count"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

type RunSummary struct {
	AlertsIn                 int            `json:"alerts_in"`
	AlertsSuppressed         int            `json:"alerts_suppressed"`
	EntityRefs               int            `json:"entity_refs"`
	StoplistedEntities       []string       `json:"stoplisted_entities"`
	LaunderingLinksRecovered int            `json:"laundering_links_recovered"`
	Incidents                int            `json:"incidents"`
	CompressionRatio         float64        `json:"compression_ratio"`
	ByPriority               map[string]int `json:"by_priority"`
	ByLabel                  map[string]int `json:"by_label"`
	ByCohesion               map[string]int `json:"by_cohesion"`
	Thresholds               domain.Bands   `json:"thresholds"`
	CasesOpened              int            `json:"cases_opened"`
	Stages                   []StageStat    `json:"stages"`
	DurationMS               int64          `json:"duration_ms"`
}

type RunParams struct {
	Config    map[string]any `json:"config"`
	Overrides *Overrides     `json:"overrides,omitempty"`
	SplitOf   *SplitRef      `json:"split_of,omitempty"`
}

type SplitRef struct {
	RunID      string `json:"run_id"`
	IncidentID string `json:"incident_id"`
	AlertA     string `json:"alert_a"`
	AlertB     string `json:"alert_b"`
}

func activeRunErr(active string) error {
	e := domain.Conflict("RUN_IN_PROGRESS", "a run is already active for this dataset; attach to %s", active)
	e.ActiveRunID = active
	return e
}

// StartRun queues a correlation run. Only one run per dataset may be active.
func (a *App) StartRun(ctx context.Context, datasetID, actor string, ov *Overrides) (Run, error) {
	d, err := a.Store.GetDataset(ctx, datasetID)
	if err != nil {
		return Run{}, err
	}
	if d.Kind == "adversarial" {
		return Run{}, domain.Unprocessable("ADVERSARIAL_MIX", "adversarial variants are correlated only by their campaign")
	}
	if d.Alerts == 0 {
		return Run{}, domain.Unprocessable("DATASET_EMPTY", "dataset %s has no alerts; simulate or ingest first", datasetID)
	}
	cuts, err := a.Store.ListCuts(ctx, datasetID)
	if err != nil {
		return Run{}, err
	}
	cfg, err := ov.apply(a.engineConfig(cuts))
	if err != nil {
		return Run{}, err
	}
	run, err := a.createRun(ctx, datasetID, actor, cfg, RunParams{Overrides: ov})
	if err != nil {
		return Run{}, err
	}
	select {
	case a.runQueue <- runJob{runID: run.RunID, datasetID: datasetID, actor: actor, cfg: cfg}:
	default:
		_ = a.Store.FailRun(ctx, run.RunID, "failed", "run queue full", a.now())
		_ = a.Store.Unlock(ctx, datasetID, run.RunID)
		return Run{}, domain.Conflict("RUN_IN_PROGRESS", "the run queue is full; try again shortly")
	}
	a.Pub.Publish(RunTopic(run.RunID), "status", map[string]any{"run_id": run.RunID, "status": "queued"})
	return run, nil
}

func (a *App) createRun(ctx context.Context, datasetID, actor string, cfg correlate.Config, params RunParams) (Run, error) {
	runID := NewID()
	ok, active, err := a.Store.TryLock(ctx, datasetID, runID, a.now(), lockTTL)
	if err != nil {
		return Run{}, err
	}
	if !ok {
		return Run{}, activeRunErr(active)
	}
	params.Config = cfg.Canonical()
	pb, _ := json.Marshal(params)
	run := Run{RunID: runID, DatasetID: datasetID, Status: "queued", RequestedBy: actor, Params: pb, CreatedAt: a.now()}
	if err := a.Store.CreateRun(ctx, run); err != nil {
		_ = a.Store.Unlock(ctx, datasetID, runID)
		return Run{}, err
	}
	return run, nil
}

func (a *App) runWorker(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		case job := <-a.runQueue:
			if _, err := a.execute(ctx, job); err != nil && !errors.Is(err, correlate.ErrCancelled) {
				a.Log.Warn("run failed", "run_id", job.runID, "err", err)
			}
		}
	}
}

// CancelRun cancels a queued or running run.
func (a *App) CancelRun(ctx context.Context, runID, actor string) (Run, error) {
	r, err := a.Store.GetRun(ctx, runID)
	if err != nil {
		return r, err
	}
	if r.Status != "queued" && r.Status != "running" {
		return r, domain.Conflict("INVALID_STATE", "run %s is already %s", runID, r.Status)
	}
	a.cancelMu.Lock()
	c, running := a.cancels[runID]
	a.cancelMu.Unlock()
	if running {
		c()
	} else {
		_ = a.Store.FailRun(ctx, runID, "cancelled", "cancelled by "+actor, a.now())
		_ = a.Store.Unlock(ctx, r.DatasetID, runID)
		a.Pub.Publish(RunTopic(runID), "status", map[string]any{"run_id": runID, "status": "cancelled"})
		a.Pub.Close(RunTopic(runID))
	}
	return a.Store.GetRun(ctx, runID)
}

type runResult struct {
	run       Run
	out       correlate.Output
	summary   RunSummary
	incidents []domain.Incident
}

// execute runs one job end to end. Everything between load and commit is the
// pure engine; the commit is one transaction.
func (a *App) execute(parent context.Context, job runJob) (res runResult, err error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), runTimeout)
	defer cancel()
	a.cancelMu.Lock()
	a.cancels[job.runID] = cancel
	a.cancelMu.Unlock()
	topic := RunTopic(job.runID)
	defer func() {
		a.cancelMu.Lock()
		delete(a.cancels, job.runID)
		a.cancelMu.Unlock()
		_ = a.Store.Unlock(context.WithoutCancel(ctx), job.datasetID, job.runID)
		if err != nil {
			status, code := "failed", "RUN_FAILED"
			if errors.Is(err, correlate.ErrCancelled) || errors.Is(err, context.Canceled) {
				status, code = "cancelled", "RUN_CANCELLED"
			}
			bg := context.WithoutCancel(ctx)
			_ = a.Store.FailRun(bg, job.runID, status, err.Error(), a.now())
			_, _ = a.audit(bg, a.Store, job.actor, "run.failed", job.runID, map[string]any{"dataset_id": job.datasetID, "reason": err.Error()})
			a.Pub.Publish(topic, "status", map[string]any{"run_id": job.runID, "status": status})
			a.Pub.Publish(topic, "error", map[string]any{"run_id": job.runID, "code": code, "message": err.Error()})
			a.Pub.Close(topic)
			a.notify("run.finished", map[string]any{"dataset_id": job.datasetID, "run_id": job.runID})
		}
	}()

	r, err := a.Store.GetRun(ctx, job.runID)
	if err != nil {
		return res, err
	}
	if r.Status != "queued" {
		return res, fmt.Errorf("run %s is %s, not queued", job.runID, r.Status)
	}
	started := a.now()
	if err := a.Store.StartRun(ctx, job.runID, started); err != nil {
		return res, err
	}
	a.Pub.Publish(topic, "status", map[string]any{"run_id": job.runID, "status": "running"})
	a.notify("run.started", map[string]any{"dataset_id": job.datasetID, "run_id": job.runID})
	if _, err := a.audit(ctx, a.Store, job.actor, "run.started", job.runID, map[string]any{"dataset_id": job.datasetID}); err != nil {
		return res, err
	}

	wall := time.Now()
	mark := wall
	var stages []StageStat
	stage := func(name string, count int) {
		now := time.Now()
		st := StageStat{Stage: name, Count: count, ElapsedMS: now.Sub(mark).Milliseconds()}
		mark = now
		stages = append(stages, st)
		a.Pub.Publish(topic, "stage", map[string]any{"run_id": job.runID, "stage": st.Stage, "count": st.Count, "elapsed_ms": st.ElapsedMS})
	}

	alerts, err := a.Store.LoadAlerts(ctx, job.datasetID)
	if err != nil {
		return res, err
	}
	assets, err := a.Store.AssetMap(ctx)
	if err != nil {
		return res, err
	}
	stats, err := a.Store.RuleStatMap(ctx)
	if err != nil {
		return res, err
	}
	sups, err := a.Store.ListSuppressions(ctx)
	if err != nil {
		return res, err
	}
	stage("load", len(alerts))

	out, err := correlate.Run(correlate.Input{
		DatasetID: job.datasetID, Alerts: alerts, Assets: assets, RuleStats: stats, Suppressed: sups,
		Attack: a.Attack, Config: job.cfg, RunStarted: started,
	}, correlate.Hooks{
		Progress:  func(s correlate.Stage) { stage(s.Name, s.Count) },
		Cancelled: func() bool { return ctx.Err() != nil },
	})
	if err != nil {
		return res, err
	}

	// compliance cases: detected_at is frozen the first time an incident
	// triggers and never recomputed, so a re-run cannot move a deadline
	byID := make(map[string]domain.Alert, len(alerts))
	for _, al := range alerts {
		byID[al.ID] = al
	}
	members := func(inc domain.Incident) []domain.Alert {
		ms := make([]domain.Alert, 0, len(inc.AlertIDs))
		for _, id := range inc.AlertIDs {
			ms = append(ms, byID[id])
		}
		return ms
	}
	var cases []Case
	facts := map[string]string{}
	for _, inc := range out.Incidents {
		facts[inc.ID] = narrate.BuildFacts(inc, members(inc), assets, a.Attack).Hash()
		if inc.Breach == nil {
			continue
		}
		if _, err := a.Store.CaseByIncident(ctx, inc.ID); err == nil {
			continue
		} else if de, ok := domain.AsError(err); !ok || de.Code != "NOT_FOUND" {
			return res, err
		}
		cases = append(cases, a.buildCase(inc, members(inc), assets, job, started))
	}
	if len(cases) > 0 {
		next, err := a.Store.NextCaseID(ctx)
		if err != nil {
			return res, err
		}
		var n int
		fmt.Sscanf(next, "CASE-%d", &n)
		for i := range cases {
			cases[i].CaseID = fmt.Sprintf("CASE-%04d", n+i)
		}
	}

	finished := a.now()
	summary := RunSummary{
		AlertsIn: out.AlertsIn, AlertsSuppressed: out.AlertsSuppressed, EntityRefs: out.EntityRefs,
		StoplistedEntities: nonNil(out.Stoplist), LaunderingLinksRecovered: out.LaunderingLinks,
		Incidents: len(out.Incidents), Thresholds: out.Bands, CasesOpened: len(cases),
		ByPriority: map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0},
		ByLabel:    map[string]int{"attack_chain": 0, "noise_cluster": 0, "single": 0},
		ByCohesion: map[string]int{"solid": 0, "moderate": 0, "fragile": 0},
	}
	for _, inc := range out.Incidents {
		summary.ByPriority[inc.Priority]++
		summary.ByLabel[inc.Label]++
		summary.ByCohesion[inc.Cohesion]++
	}
	if len(out.Incidents) > 0 {
		summary.CompressionRatio = risk.Round2(float64(out.AlertsIn) / float64(len(out.Incidents)))
	}

	cfgFull := job.cfg.Canonical()
	cfgFull["engine_version"] = EngineVersion
	cfgFull["attack_version"] = a.Attack.Version
	cfgFull["attack_bundle_hash"] = a.Attack.Hash
	cfgFull["assets_hash"] = receipt.AssetsHash(assets)
	cfgFull["rule_stats_hash"] = receipt.RuleStatsHash(stats)
	cfgFull["suppressions_hash"] = receipt.SuppressionsHash(sups, started)

	var params RunParams
	_ = json.Unmarshal(r.Params, &params)
	params.Config = cfgFull
	pb, _ := json.Marshal(params)
	r.Params = pb
	r.InputHash = receipt.InputHash(alerts)
	r.ConfigHash = receipt.ConfigHash(cfgFull)
	r.OutputHash = receipt.OutputHash(out.Incidents)
	r.EngineVersion, r.AttackVersion, r.Dialect = EngineVersion, a.Attack.Version, a.Store.Dialect()
	r.Bands = &out.Bands
	r.StartedAt, r.FinishedAt, r.ComputedAt = &started, &finished, &finished

	commitStart := time.Now()
	err = a.Store.InTx(ctx, func(tx Store) error {
		summary.Stages = append(stages, StageStat{Stage: "commit", Count: len(out.Incidents)})
		summary.DurationMS = time.Since(wall).Milliseconds()
		sb, _ := json.Marshal(summary)
		r.Summary = sb
		if err := tx.CommitRun(ctx, CommitSet{Run: r, Incidents: out.Incidents, FactsHash: facts, Cases: cases, SetCurrent: true}); err != nil {
			return err
		}
		if _, err := a.audit(ctx, tx, job.actor, "run.succeeded", job.runID, map[string]any{
			"dataset_id": job.datasetID, "incidents": len(out.Incidents), "output_hash": r.OutputHash}); err != nil {
			return err
		}
		for _, c := range cases {
			if _, err := a.audit(ctx, tx, "system", "case.opened", c.CaseID, map[string]any{
				"incident_id": c.IncidentID, "detected_at": c.DetectedAt.Format(time.RFC3339), "evidence_hash": c.EvidenceHash}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	commitMS := time.Since(commitStart).Milliseconds()
	summary.Stages[len(summary.Stages)-1].ElapsedMS = commitMS
	summary.DurationMS = time.Since(wall).Milliseconds()
	a.Pub.Publish(topic, "stage", map[string]any{"run_id": job.runID, "stage": "commit", "count": len(out.Incidents), "elapsed_ms": commitMS})
	a.Pub.Publish(topic, "status", map[string]any{"run_id": job.runID, "status": "succeeded"})
	a.Pub.Publish(topic, "done", map[string]any{"run_id": job.runID, "summary": summary})
	a.Pub.Close(topic)
	a.notify("run.finished", map[string]any{"dataset_id": job.datasetID, "run_id": job.runID})
	for _, c := range cases {
		a.notify("case.opened", map[string]any{"dataset_id": job.datasetID, "incident_id": c.IncidentID, "case_id": c.CaseID})
	}
	if !job.internal || params.SplitOf != nil {
		a.prewarm(job.runID, out.Incidents)
	}
	r.Status = "succeeded"
	return runResult{run: r, out: out, summary: summary, incidents: out.Incidents}, nil
}

func (a *App) buildCase(inc domain.Incident, alerts []domain.Alert, assets map[string]domain.Asset, job runJob, detected time.Time) Case {
	ev := compliance.Evidence{Incident: inc, Alerts: alerts, Assets: assets, DetectedAt: detected}
	c := Case{IncidentID: inc.ID, DatasetID: job.datasetID, RunID: job.runID, Priority: inc.Priority, Headline: inc.Headline,
		DetectedAt: detected, Trigger: *inc.Breach, EvidenceHash: ev.Hash()}
	gen := detected
	for _, t := range compliance.Tracks {
		draft, _ := json.Marshal(compliance.Draft(t.Name, ev))
		c.Tracks = append(c.Tracks, Track{Track: t.Name, Deadline: detected.Add(t.Offset), Status: "drafted", Draft: draft, GeneratedAt: &gen})
	}
	return c
}

// Receipt is the determinism receipt for a run.
type Receipt struct {
	RunID         string         `json:"run_id"`
	DatasetID     string         `json:"dataset_id"`
	Scheme        string         `json:"scheme"`
	InputHash     string         `json:"input_hash"`
	ConfigHash    string         `json:"config_hash"`
	OutputHash    string         `json:"output_hash"`
	EngineVersion string         `json:"engine_version"`
	AttackVersion string         `json:"attack_version"`
	Dialect       string         `json:"dialect"`
	ComputedAt    *time.Time     `json:"computed_at"`
	Config        map[string]any `json:"config"`
}

func (a *App) GetReceipt(ctx context.Context, runID string) (Receipt, error) {
	r, err := a.Store.GetRun(ctx, runID)
	if err != nil {
		return Receipt{}, err
	}
	if r.Status != "succeeded" {
		return Receipt{}, domain.Unprocessable("RUN_NOT_SUCCEEDED", "run %s is %s; only succeeded runs have a receipt", runID, r.Status)
	}
	var p RunParams
	_ = json.Unmarshal(r.Params, &p)
	return Receipt{RunID: r.RunID, DatasetID: r.DatasetID, Scheme: receipt.Scheme, InputHash: r.InputHash, ConfigHash: r.ConfigHash,
		OutputHash: r.OutputHash, EngineVersion: r.EngineVersion, AttackVersion: r.AttackVersion, Dialect: r.Dialect,
		ComputedAt: r.ComputedAt, Config: p.Config}, nil
}

// maintenance reaps stale run locks every minute and applies retention daily.
func (a *App) maintenance(ctx context.Context) {
	defer a.wg.Done()
	t := time.NewTicker(maintenanceTick)
	defer t.Stop()
	lastRetention := time.Time{}
	for {
		reaped, err := a.Store.ReapStaleLocks(ctx, a.now())
		if err == nil {
			for _, l := range reaped {
				_ = a.Store.FailRun(ctx, l.RunID, "failed", "run lock expired (process crashed or run exceeded its lease)", a.now())
				a.Log.Warn("reaped stale run lock", "dataset_id", l.DatasetID, "run_id", l.RunID)
			}
		}
		if time.Since(lastRetention) > 24*time.Hour {
			lastRetention = time.Now()
			if n, err := a.Store.DropExpired(ctx, a.now().AddDate(0, 0, -RetentionDays)); err != nil {
				a.Log.Warn("retention", "err", err)
			} else if n > 0 {
				a.Log.Info("retention dropped expired log rows", "rows", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		case <-t.C:
		}
	}
}

const RetentionDays = 180

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	sort.Strings(xs)
	return xs
}

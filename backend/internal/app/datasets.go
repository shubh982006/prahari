package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

type DatasetView struct {
	Dataset
	Counts DatasetCounts `json:"counts"`
}

type DatasetCounts struct {
	AuthEvents       int `json:"auth_events"`
	Alerts           int `json:"alerts"`
	AlertsByDetector int `json:"alerts_by_detector"`
}

func ViewDataset(d Dataset) DatasetView {
	if d.Scenarios == nil {
		d.Scenarios = []string{}
	}
	return DatasetView{Dataset: d, Counts: DatasetCounts{d.AuthEvents, d.Alerts, d.AlertsByDetector}}
}

var datasetIDRe = regexp.MustCompile(`^ds_[a-z0-9_]{3,60}$`)

func ValidDatasetID(id string) bool { return datasetIDRe.MatchString(id) }

func (a *App) truthPath(datasetID string) string {
	return filepath.Join(a.DataDir, "truth", datasetID+".json")
}

// writeTruth stores ground truth in the database, so it survives hosts whose
// local disk is wiped on restart. The API never returns it and the engine
// never reads it; only evaluation and the adversary bench do.
func (a *App) writeTruth(ctx context.Context, t domain.Truth) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return a.Store.PutTruth(ctx, t.DatasetID, b, a.now())
}

// readTruth reads from the database. A truth file left by an older version
// is read once and copied in, so existing installations migrate themselves.
func (a *App) readTruth(ctx context.Context, datasetID string) (domain.Truth, error) {
	var t domain.Truth
	b, err := a.Store.GetTruth(ctx, datasetID)
	if err != nil {
		if de, ok := domain.AsError(err); !ok || de.Code != "NOT_FOUND" {
			return t, err
		}
		file, ferr := os.ReadFile(a.truthPath(datasetID))
		if ferr != nil {
			return t, domain.Unprocessable("NO_GROUND_TRUTH", "dataset %s has no ground truth; evaluation needs a simulated dataset", datasetID)
		}
		if err := a.Store.PutTruth(ctx, datasetID, file, a.now()); err != nil {
			a.Log.Warn("backfill ground truth", "dataset_id", datasetID, "err", err)
		}
		b = file
	}
	return t, json.Unmarshal(b, &t)
}

// Simulate generates a dataset deterministically and ingests it through the
// same pipeline as an upload, so detector alerts are raised exactly as they
// would be for real logs.
func (a *App) Simulate(ctx context.Context, p simulate.Params, actor string) (Dataset, error) {
	p = p.WithDefaults()
	sim := simulate.Generate(p)
	if existing, err := a.Store.GetDataset(ctx, sim.DatasetID); err == nil {
		return existing, domain.Conflict("ALREADY_EXISTS", "dataset %s already exists for seed %d and this start time", existing.DatasetID, p.Seed)
	}
	seed := p.Seed
	d := Dataset{DatasetID: sim.DatasetID, Kind: "simulated", Seed: &seed, WindowStart: p.Start, WindowEnd: sim.End,
		Scenarios: append([]string(nil), p.Scenarios...), HasTruth: true, CreatedAt: a.now()}
	if err := a.Store.CreateDataset(ctx, d); err != nil {
		return d, err
	}
	if err := a.writeTruth(ctx, sim.Truth); err != nil {
		return d, err
	}
	var events, alerts bytes.Buffer
	enc := json.NewEncoder(&events)
	for _, e := range sim.AuthEvents {
		_ = enc.Encode(map[string]any{"event_id": e.EventID, "timestamp": e.TS.Format(time.RFC3339Nano), "username": e.Username,
			"src_ip": e.SrcIP, "geo": e.Geo, "result": e.Result, "app": e.App, "is_admin": e.IsAdmin})
	}
	enc = json.NewEncoder(&alerts)
	for _, al := range sim.Alerts {
		_ = enc.Encode(alertInputOf(al))
	}
	if _, err := a.IngestAuthEvents(ctx, d.DatasetID, actor, &events); err != nil {
		return d, fmt.Errorf("simulate: auth events: %w", err)
	}
	if _, err := a.IngestAlerts(ctx, d.DatasetID, actor, &alerts); err != nil {
		return d, fmt.Errorf("simulate: alerts: %w", err)
	}
	if _, err := a.audit(ctx, a.Store, actor, "dataset.created", d.DatasetID, map[string]any{"kind": "simulated", "seed": p.Seed, "scenarios": p.Scenarios}); err != nil {
		return d, err
	}
	a.notify("dataset.created", map[string]any{"dataset_id": d.DatasetID})
	return a.Store.GetDataset(ctx, d.DatasetID)
}

func alertInputOf(al domain.Alert) map[string]any {
	m := map[string]any{"id": al.ID, "timestamp": al.TS.Format(time.RFC3339Nano), "source": al.Source, "rule_id": al.RuleID,
		"rule_name": al.RuleName, "severity": al.Severity, "entities": al.Entities.Normalized(), "raw": json.RawMessage(al.Raw)}
	if al.TechniqueID != "" {
		m["technique_id"] = al.TechniqueID
	}
	if len(al.Raw) == 0 {
		m["raw"] = map[string]any{}
	}
	return m
}

// CreateDataset registers an empty dataset for external NDJSON ingest.
func (a *App) CreateDataset(ctx context.Context, id string, from, to time.Time, actor string) (Dataset, error) {
	if !ValidDatasetID(id) {
		return Dataset{}, domain.Validation(domain.FieldError{Field: "body.dataset_id", Message: "must match ^ds_[a-z0-9_]{3,60}$"})
	}
	if !to.After(from) {
		return Dataset{}, domain.Validation(domain.FieldError{Field: "body.window_end", Message: "must be after window_start"})
	}
	d := Dataset{DatasetID: id, Kind: "ingested", WindowStart: from.UTC(), WindowEnd: to.UTC(), Scenarios: []string{}, CreatedAt: a.now()}
	if err := a.Store.CreateDataset(ctx, d); err != nil {
		return d, err
	}
	if _, err := a.audit(ctx, a.Store, actor, "dataset.created", id, map[string]any{"kind": "ingested"}); err != nil {
		return d, err
	}
	a.notify("dataset.created", map[string]any{"dataset_id": id})
	return d, nil
}

// SeedDemo creates and correlates the seed-42 dataset on an empty database,
// so a fresh clone has something to look at within seconds, then prewarms the
// evaluation and adversary bench so no demo panel opens empty.
func (a *App) SeedDemo(ctx context.Context) error {
	id := simulate.DatasetID(simulate.Params{Seed: 42})
	if d, err := a.Store.GetDataset(ctx, id); err == nil && d.CurrentRunID != nil {
		return a.prewarmDemo(ctx, id, *d.CurrentRunID)
	}
	if _, err := a.Store.GetDataset(ctx, id); err != nil {
		if _, err := a.Simulate(ctx, simulate.Params{Seed: 42}, "system"); err != nil {
			return err
		}
	}
	run, err := a.StartRun(ctx, id, "system", nil)
	if err != nil {
		if de, ok := domain.AsError(err); ok && de.Code == "RUN_IN_PROGRESS" {
			return nil
		}
		return err
	}
	a.Log.Info("demo dataset seeded", "dataset_id", id, "run_id", run.RunID)
	return a.prewarmDemo(ctx, id, run.RunID)
}

// ---------- alerts ----------

type AlertQuery struct {
	DatasetID string
	From, To  *time.Time
	Sources   []string
	Severity  []string
	RuleID    string
	Entity    string
	Q         string
	Desc      bool
	Limit     int
	Cursor    string
}

type alertCursor struct {
	DS string    `json:"d"`
	TS time.Time `json:"t"`
	ID string    `json:"i"`
}

func (a *App) ListAlerts(ctx context.Context, q AlertQuery) ([]AlertView, *string, error) {
	if _, err := a.Store.GetDataset(ctx, q.DatasetID); err != nil {
		return nil, nil, err
	}
	f := AlertFilter{DatasetID: q.DatasetID, From: q.From, To: q.To, Sources: q.Sources, Severity: q.Severity, RuleID: q.RuleID,
		Entity: strings.ToLower(q.Entity), Q: q.Q, Desc: q.Desc, Limit: q.Limit + 1}
	if q.Cursor != "" {
		var c alertCursor
		if err := a.DecodeCursor(q.Cursor, &c); err != nil || c.DS != q.DatasetID {
			return nil, nil, domain.E(400, "INVALID_CURSOR", "cursor is invalid for this dataset; restart from the first page")
		}
		f.After = &AlertCursor{TS: c.TS, ID: c.ID}
	}
	rows, err := a.Store.ListAlerts(ctx, f)
	if err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		last := rows[len(rows)-1]
		c := a.EncodeCursor(alertCursor{q.DatasetID, last.TS, last.ID})
		next = &c
	}
	out := make([]AlertView, len(rows))
	for i, r := range rows {
		v := a.AlertView(r)
		v.Raw = nil
		out[i] = v
	}
	return out, next, nil
}

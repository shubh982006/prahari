package app

import (
	"context"
	"encoding/json"
	"time"

	"prahari/internal/core/compliance"
	"prahari/internal/domain"
)

type TrackView struct {
	Track            string     `json:"track"`
	Authority        string     `json:"authority"`
	Basis            string     `json:"basis"`
	Deadline         time.Time  `json:"deadline"`
	DeadlineKind     string     `json:"deadline_kind"`
	Status           string     `json:"status"`
	Overdue          bool       `json:"overdue"`
	RemainingSeconds int64      `json:"remaining_seconds"`
	SubmittedAt      *time.Time `json:"submitted_at"`
	SubmittedBy      *string    `json:"submitted_by"`
	Reference        *string    `json:"reference"`
}

type CaseView struct {
	CaseID     string               `json:"case_id"`
	IncidentID string               `json:"incident_id"`
	DatasetID  string               `json:"dataset_id"`
	RunID      string               `json:"run_id"`
	Priority   string               `json:"priority"`
	Headline   string               `json:"headline"`
	DetectedAt time.Time            `json:"detected_at"`
	Trigger    domain.BreachTrigger `json:"trigger"`
	Tracks     []TrackView          `json:"tracks"`
	State      string               `json:"state"`
}

type EvidenceItem struct {
	TS       time.Time `json:"ts"`
	Kind     string    `json:"kind"`
	Ref      string    `json:"ref"`
	Summary  string    `json:"summary"`
	AuditSeq *int64    `json:"audit_seq,omitempty"`
}

type CaseDetailView struct {
	CaseView
	EvidenceHash string         `json:"evidence_hash"`
	Evidence     []EvidenceItem `json:"evidence"`
}

// caseView computes live deadline state at now. remaining_seconds is relative
// to the server_time the response carries, so the UI can correct drift.
func caseView(c Case, now time.Time) CaseView {
	v := CaseView{CaseID: c.CaseID, IncidentID: c.IncidentID, DatasetID: c.DatasetID, RunID: c.RunID, Priority: c.Priority,
		Headline: c.Headline, DetectedAt: c.DetectedAt, Trigger: c.Trigger, Tracks: []TrackView{}}
	closed, overdue := true, false
	for _, t := range c.Tracks {
		def, _ := compliance.TrackByName(t.Track)
		tv := TrackView{Track: t.Track, Authority: def.Authority, Basis: def.Basis, Deadline: t.Deadline, DeadlineKind: def.DeadlineKind,
			Status: t.Status, SubmittedAt: t.SubmittedAt, SubmittedBy: t.SubmittedBy, Reference: t.Reference,
			RemainingSeconds: int64(t.Deadline.Sub(now).Seconds())}
		if t.SubmittedAt == nil {
			closed = false
			tv.Overdue = now.After(t.Deadline)
			overdue = overdue || tv.Overdue
		}
		v.Tracks = append(v.Tracks, tv)
	}
	switch {
	case closed:
		v.State = "closed"
	case overdue:
		v.State = "overdue"
	default:
		v.State = "open"
	}
	return v
}

func (a *App) ListCases(ctx context.Context, datasetID, state string) ([]CaseView, time.Time, error) {
	now := a.now()
	cs, err := a.Store.ListCases(ctx, datasetID)
	if err != nil {
		return nil, now, err
	}
	out := []CaseView{}
	for _, c := range cs {
		v := caseView(c, now)
		switch state {
		case "all":
		case "open", "":
			if v.State == "closed" {
				continue
			}
		default:
			if v.State != state {
				continue
			}
		}
		out = append(out, v)
	}
	return out, now, nil
}

func (a *App) GetCase(ctx context.Context, caseID string) (CaseDetailView, time.Time, error) {
	now := a.now()
	c, err := a.Store.GetCase(ctx, caseID)
	if err != nil {
		return CaseDetailView{}, now, err
	}
	v := CaseDetailView{CaseView: caseView(c, now), EvidenceHash: c.EvidenceHash, Evidence: []EvidenceItem{}}
	if row, err := a.Store.GetIncident(ctx, c.RunID, c.IncidentID); err == nil {
		if alerts, err := a.Store.AlertsByID(ctx, c.DatasetID, row.Incident.ChainIDs); err == nil {
			for _, al := range alerts {
				v.Evidence = append(v.Evidence, EvidenceItem{TS: al.TS, Kind: "alert", Ref: al.ID, Summary: al.RuleName})
			}
		}
	}
	for _, subject := range []string{c.IncidentID, c.CaseID, c.RunID} {
		entries, err := a.Store.ListAudit(ctx, subject, "", 200, 0)
		if err != nil {
			return v, now, err
		}
		for _, e := range entries {
			kind := map[string]string{"run.succeeded": "run", "feedback.created": "feedback", "narrative.generated": "narrative",
				"draft.generated": "draft", "submission.recorded": "submission", "case.opened": "run", "incident.updated": "feedback"}[e.Action]
			if kind == "" {
				continue
			}
			seq := e.Seq
			v.Evidence = append(v.Evidence, EvidenceItem{TS: e.TS, Kind: kind, Ref: e.Action, Summary: summarise(e), AuditSeq: &seq})
		}
	}
	sortEvidence(v.Evidence)
	return v, now, nil
}

func summarise(e AuditEntry) string {
	var p map[string]any
	_ = json.Unmarshal(e.Payload, &p)
	switch e.Action {
	case "submission.recorded":
		return "submitted " + str(p["track"]) + " (" + str(p["reference"]) + ")"
	case "feedback.created":
		return "verdict: " + str(p["verdict"])
	case "narrative.generated":
		return "brief generated from " + str(p["source"])
	case "case.opened":
		return "case opened; clock started"
	case "run.succeeded":
		return "correlation run committed"
	}
	return e.Action
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func sortEvidence(xs []EvidenceItem) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j].TS.Before(xs[j-1].TS); j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}

type DraftView struct {
	CaseID       string         `json:"case_id"`
	Track        string         `json:"track"`
	GeneratedAt  time.Time      `json:"generated_at"`
	EvidenceHash string         `json:"evidence_hash"`
	Disclaimer   string         `json:"disclaimer"`
	Fields       map[string]any `json:"fields"`
}

func (a *App) Draft(ctx context.Context, caseID, track string) (DraftView, string, error) {
	if _, ok := compliance.TrackByName(track); !ok {
		return DraftView{}, "", domain.NotFound("track " + track)
	}
	c, err := a.Store.GetCase(ctx, caseID)
	if err != nil {
		return DraftView{}, "", err
	}
	t, err := a.Store.GetTrack(ctx, caseID, track)
	if err != nil {
		return DraftView{}, "", err
	}
	var fields map[string]any
	_ = json.Unmarshal(t.Draft, &fields)
	gen := c.DetectedAt
	if t.GeneratedAt != nil {
		gen = *t.GeneratedAt
	}
	v := DraftView{CaseID: caseID, Track: track, GeneratedAt: gen, EvidenceHash: c.EvidenceHash, Disclaimer: compliance.Disclaimer, Fields: fields}
	return v, compliance.Markdown(caseID, track, fields, gen, c.EvidenceHash), nil
}

// RecordSubmission records that a human submitted a track. Prahari never
// contacts a regulator.
func (a *App) RecordSubmission(ctx context.Context, caseID, track, actor, reference, note string, at time.Time) (CaseView, error) {
	if _, ok := compliance.TrackByName(track); !ok {
		return CaseView{}, domain.NotFound("track " + track)
	}
	err := a.Store.InTx(ctx, func(tx Store) error {
		if err := tx.RecordSubmission(ctx, caseID, track, actor, reference, note, at); err != nil {
			return err
		}
		_, err := a.audit(ctx, tx, actor, "submission.recorded", caseID, map[string]any{"track": track, "reference": reference, "submitted_at": at.Format(time.RFC3339)})
		return err
	})
	if err != nil {
		return CaseView{}, err
	}
	c, err := a.Store.GetCase(ctx, caseID)
	if err != nil {
		return CaseView{}, err
	}
	return caseView(c, a.now()), nil
}

type RetentionView struct {
	PolicyDays int             `json:"policy_days"`
	Basis      string          `json:"basis"`
	Dialect    string          `json:"dialect"`
	Mechanism  string          `json:"mechanism"`
	NextRunAt  time.Time       `json:"next_run_at"`
	Units      []RetentionUnit `json:"units"`
}

func (a *App) Retention(ctx context.Context) (RetentionView, error) {
	units, mech, err := a.Store.RetentionInventory(ctx)
	if err != nil {
		return RetentionView{}, err
	}
	if units == nil {
		units = []RetentionUnit{}
	}
	now := a.now()
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return RetentionView{PolicyDays: RetentionDays, Basis: "CERT-In Directions: maintain ICT system logs for 180 days",
		Dialect: a.Store.Dialect(), Mechanism: mech, NextRunAt: next, Units: units}, nil
}

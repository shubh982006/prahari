package app

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"prahari/internal/core/evaluate"
	"prahari/internal/domain"
)

// Evaluate scores a run against its dataset's ground truth. Always reported
// with the baseline it is measured against.
func (a *App) Evaluate(ctx context.Context, runID string, model evaluate.AnalystModel, actor string) (EvaluationView, error) {
	run, err := a.Store.GetRun(ctx, runID)
	if err != nil {
		return EvaluationView{}, err
	}
	if run.Status != "succeeded" {
		return EvaluationView{}, domain.Unprocessable("RUN_NOT_SUCCEEDED", "run %s is %s", runID, run.Status)
	}
	truth, err := a.readTruth(ctx, run.DatasetID)
	if err != nil {
		return EvaluationView{}, err
	}
	rows, err := a.Store.ListIncidents(ctx, runID)
	if err != nil {
		return EvaluationView{}, err
	}
	incs := make([]domain.Incident, len(rows))
	for i, r := range rows {
		incs[i] = r.Incident
	}
	alerts, err := a.Store.LoadAlerts(ctx, run.DatasetID)
	if err != nil {
		return EvaluationView{}, err
	}
	if model.SecondsPerAlert <= 0 {
		model.SecondsPerAlert = evaluate.DefaultAnalyst.SecondsPerAlert
	}
	if model.SecondsPerIncident <= 0 {
		model.SecondsPerIncident = evaluate.DefaultAnalyst.SecondsPerIncident
	}
	m, sc := evaluate.Evaluate(incs, truth, alertOrder(alerts), model)
	var summary RunSummary
	_ = json.Unmarshal(run.Summary, &summary)
	m.CorrelateMS = summary.DurationMS
	mb, _ := json.Marshal(m)
	if sc == nil {
		sc = []evaluate.Scenario{}
	}
	sb, _ := json.Marshal(sc)
	amb, _ := json.Marshal(model)
	v := EvaluationView{EvaluationID: "ev_" + strings.ReplaceAll(NewID(), "-", "")[:16], RunID: runID, DatasetID: run.DatasetID,
		CreatedAt: a.now(), AnalystModel: amb, Baseline: evaluate.Baseline(model), Metrics: mb, Scenarios: sb}
	body, _ := json.Marshal(v)
	if err := a.Store.PutEvaluation(ctx, Evaluation{EvaluationID: v.EvaluationID, RunID: runID, DatasetID: run.DatasetID, CreatedAt: v.CreatedAt, Body: body}); err != nil {
		return v, err
	}
	a.notify("evaluation.finished", map[string]any{"dataset_id": run.DatasetID, "run_id": runID})
	return v, nil
}

func (a *App) LatestEvaluation(ctx context.Context, datasetID string) (json.RawMessage, error) {
	e, err := a.Store.LatestEvaluation(ctx, datasetID)
	if err != nil {
		return nil, err
	}
	return e.Body, nil
}

// ---------- audit ----------

type AuditVerify struct {
	OK         bool      `json:"ok"`
	Checked    int64     `json:"checked"`
	HeadHash   string    `json:"head_hash"`
	BrokenSeq  *int64    `json:"broken_seq"`
	VerifiedAt time.Time `json:"verified_at"`
}

// VerifyAudit recomputes the chain and reports the first broken link.
func (a *App) VerifyAudit(ctx context.Context) (AuditVerify, error) {
	v := AuditVerify{OK: true, HeadHash: GenesisHash}
	prev := GenesisHash
	want := int64(1)
	err := a.Store.WalkAudit(ctx, func(e AuditEntry) error {
		v.Checked++
		subject := ""
		if e.Subject != nil {
			subject = *e.Subject
		}
		if v.OK && (e.Seq != want || e.PrevHash != prev || AuditHash(prev, e.TS, e.Actor, e.Action, subject, e.Payload) != e.Hash) {
			v.OK = false
			seq := e.Seq
			v.BrokenSeq = &seq
		}
		prev, want = e.Hash, e.Seq+1
		v.HeadHash = e.Hash
		return nil
	})
	v.VerifiedAt = a.now()
	return v, err
}

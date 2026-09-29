package app

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"

	"prahari/internal/core/counterfactual"
	"prahari/internal/domain"
)

// ---------- views ----------

type IncidentSummaryView struct {
	IncidentID         string    `json:"incident_id"`
	RunID              string    `json:"run_id"`
	Rank               int       `json:"rank"`
	Headline           string    `json:"headline"`
	Label              string    `json:"label"`
	Priority           string    `json:"priority"`
	Risk               float64   `json:"risk"`
	Confidence         float64   `json:"confidence"`
	Cohesion           string    `json:"cohesion"`
	Status             string    `json:"status"`
	Assignee           *string   `json:"assignee"`
	AlertCount         int       `json:"alert_count"`
	Stages             []int     `json:"stages"`
	MaxStage           int       `json:"max_stage"`
	ForwardStages      int       `json:"forward_stages"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	Assets             []string  `json:"assets"`
	LaunderingInferred bool      `json:"laundering_inferred"`
	HasCase            bool      `json:"has_case"`
	CaseID             *string   `json:"case_id"`
}

type IncidentDetailView struct {
	IncidentSummaryView
	CohesionReason string                     `json:"cohesion_reason"`
	Breakdown      domain.Breakdown           `json:"breakdown"`
	Entities       []domain.IncidentEntity    `json:"entities"`
	Techniques     []domain.IncidentTechnique `json:"techniques"`
	Sources        map[string]int             `json:"sources"`
	ETag           string                     `json:"etag"`
}

func summaryView(r IncidentRow) IncidentSummaryView {
	inc := r.Incident
	return IncidentSummaryView{
		IncidentID: inc.ID, RunID: r.RunID, Rank: inc.Rank, Headline: inc.Headline, Label: inc.Label, Priority: inc.Priority,
		Risk: inc.Risk, Confidence: inc.Confidence, Cohesion: inc.Cohesion, Status: r.State.Status, Assignee: r.State.Assignee,
		AlertCount: len(inc.AlertIDs), Stages: inc.Stages, MaxStage: inc.MaxStage, ForwardStages: inc.ForwardStages,
		FirstSeen: inc.FirstSeen, LastSeen: inc.LastSeen, Assets: inc.Assets, LaunderingInferred: inc.LaunderingInferred,
		HasCase: r.CaseID != nil, CaseID: r.CaseID,
	}
}

func IncidentETag(id string, version int) string { return fmt.Sprintf(`"inc:%s:v%d"`, id, version) }

func detailView(r IncidentRow) IncidentDetailView {
	inc := r.Incident
	b := inc.Breakdown
	if b.Rules == nil {
		b.Rules = []domain.BreakdownRule{}
	}
	return IncidentDetailView{IncidentSummaryView: summaryView(r), CohesionReason: inc.CohesionReason, Breakdown: b,
		Entities: inc.Entities, Techniques: inc.Techniques, Sources: inc.Sources, ETag: IncidentETag(inc.ID, r.State.Version)}
}

// ---------- run resolution ----------

// ResolveRun returns the run to read: the one named, or the dataset's current
// run.
func (a *App) ResolveRun(ctx context.Context, datasetID, runID string) (string, error) {
	if runID != "" {
		r, err := a.Store.GetRun(ctx, runID)
		if err != nil {
			return "", err
		}
		if datasetID != "" && r.DatasetID != datasetID {
			return "", domain.NotFound("run " + runID + " in dataset " + datasetID)
		}
		if r.Status != "succeeded" {
			return "", domain.Unprocessable("RUN_NOT_SUCCEEDED", "run %s is %s", runID, r.Status)
		}
		return runID, nil
	}
	d, err := a.Store.GetDataset(ctx, datasetID)
	if err != nil {
		return "", err
	}
	if d.CurrentRunID == nil {
		return "", domain.NotFound("a completed run for dataset " + datasetID)
	}
	return *d.CurrentRunID, nil
}

// incidentRun finds which run to read an incident from when the caller gives
// no run: the current run of the most recent dataset that holds it.
func (a *App) incidentRun(ctx context.Context, incidentID, runID string) (string, error) {
	if runID != "" {
		return runID, nil
	}
	ds, err := a.Store.ListDatasets(ctx, "", 500, nil, "")
	if err != nil {
		return "", err
	}
	for _, d := range ds {
		if d.CurrentRunID == nil || d.Kind == "adversarial" {
			continue
		}
		if _, err := a.Store.GetIncident(ctx, *d.CurrentRunID, incidentID); err == nil {
			return *d.CurrentRunID, nil
		}
	}
	return "", domain.NotFound("incident " + incidentID)
}

// ---------- list ----------

type IncidentFilter struct {
	DatasetID, RunID string
	Priority, Label  []string
	Status, Cohesion []string
	Asset, Assignee  string
	Breach           *bool
	Sort             string
	Limit            int
	Cursor           string
}

type IncidentList struct {
	RunID      string                `json:"run_id"`
	Totals     IncidentTotals        `json:"totals"`
	Thresholds domain.Bands          `json:"thresholds"`
	Data       []IncidentSummaryView `json:"data"`
	NextCursor *string               `json:"-"`
	ETag       string                `json:"-"`
}

type IncidentTotals struct {
	Incidents  int            `json:"incidents"`
	Alerts     int            `json:"alerts"`
	ByPriority map[string]int `json:"by_priority"`
}

type incCursor struct {
	Run string `json:"r"`
	ID  string `json:"i"`
}

func in(xs []string, v string) bool {
	if len(xs) == 0 {
		return true
	}
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func (a *App) ListIncidents(ctx context.Context, f IncidentFilter) (IncidentList, error) {
	runID, err := a.ResolveRun(ctx, f.DatasetID, f.RunID)
	if err != nil {
		return IncidentList{}, err
	}
	run, err := a.Store.GetRun(ctx, runID)
	if err != nil {
		return IncidentList{}, err
	}
	rows, err := a.Store.ListIncidents(ctx, runID)
	if err != nil {
		return IncidentList{}, err
	}
	out := IncidentList{RunID: runID, Totals: IncidentTotals{ByPriority: map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0}}, Data: []IncidentSummaryView{}}
	if run.Bands != nil {
		out.Thresholds = *run.Bands
	}
	h := fnv.New64a()
	h.Write([]byte(runID))
	var filtered []IncidentRow
	for _, r := range rows {
		out.Totals.Incidents++
		out.Totals.Alerts += len(r.Incident.AlertIDs)
		out.Totals.ByPriority[r.Incident.Priority]++
		fmt.Fprintf(h, "|%s:%d:%s", r.Incident.ID, r.State.Version, r.State.Status)
		inc := r.Incident
		if !in(f.Priority, inc.Priority) || !in(f.Label, inc.Label) || !in(f.Status, r.State.Status) || !in(f.Cohesion, inc.Cohesion) {
			continue
		}
		if f.Asset != "" && !contains(inc.Assets, strings.ToLower(f.Asset)) {
			continue
		}
		if f.Assignee != "" && (r.State.Assignee == nil || *r.State.Assignee != f.Assignee) {
			continue
		}
		if f.Breach != nil && (r.CaseID != nil) != *f.Breach {
			continue
		}
		filtered = append(filtered, r)
	}
	out.ETag = fmt.Sprintf(`"run:%s:state:%x"`, runID, h.Sum64())
	switch f.Sort {
	case "risk":
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Incident.Rank > filtered[j].Incident.Rank })
	case "first_seen", "-first_seen":
		desc := f.Sort == "-first_seen"
		sort.SliceStable(filtered, func(i, j int) bool {
			a, b := filtered[i].Incident, filtered[j].Incident
			if !a.FirstSeen.Equal(b.FirstSeen) {
				return a.FirstSeen.Before(b.FirstSeen) != desc
			}
			return a.ID < b.ID
		})
	}
	start := 0
	if f.Cursor != "" {
		var c incCursor
		if err := a.DecodeCursor(f.Cursor, &c); err != nil || c.Run != runID {
			return out, domain.E(400, "INVALID_CURSOR", "cursor does not belong to this run; restart from the first page")
		}
		start = len(filtered)
		for i, r := range filtered {
			if r.Incident.ID == c.ID {
				start = i + 1
				break
			}
		}
	}
	end := min(start+f.Limit, len(filtered))
	for _, r := range filtered[start:end] {
		out.Data = append(out.Data, summaryView(r))
	}
	if end < len(filtered) {
		c := a.EncodeCursor(incCursor{runID, filtered[end-1].Incident.ID})
		out.NextCursor = &c
	}
	return out, nil
}

// ---------- detail and projections ----------

func (a *App) GetIncident(ctx context.Context, incidentID, runID string) (IncidentRow, error) {
	runID, err := a.incidentRun(ctx, incidentID, runID)
	if err != nil {
		return IncidentRow{}, err
	}
	return a.Store.GetIncident(ctx, runID, incidentID)
}

func (a *App) IncidentDetail(ctx context.Context, incidentID, runID string) (IncidentDetailView, error) {
	r, err := a.GetIncident(ctx, incidentID, runID)
	if err != nil {
		return IncidentDetailView{}, err
	}
	return detailView(r), nil
}

var transitions = map[string][]string{
	"open":           {"investigating", "confirmed", "false_positive", "closed"},
	"investigating":  {"open", "confirmed", "false_positive", "closed"},
	"confirmed":      {"investigating", "closed"},
	"false_positive": {"open", "closed"},
	"closed":         {"open"},
}

type IncidentPatch struct {
	Status      *string
	Assignee    *string
	AssigneeSet bool
}

// PatchIncident changes workflow state. It writes to incident_state, keyed on
// the stable ID, so the change survives a re-run; If-Match is mandatory.
func (a *App) PatchIncident(ctx context.Context, incidentID, runID, ifMatch, actor string, p IncidentPatch) (IncidentDetailView, error) {
	row, err := a.GetIncident(ctx, incidentID, runID)
	if err != nil {
		return IncidentDetailView{}, err
	}
	if ifMatch == "" {
		return IncidentDetailView{}, domain.E(428, "PRECONDITION_REQUIRED", "send If-Match with the ETag from your last GET")
	}
	if ifMatch != IncidentETag(incidentID, row.State.Version) && ifMatch != "*" {
		return IncidentDetailView{}, domain.E(412, "PRECONDITION_FAILED", "incident %s changed since you read it", incidentID)
	}
	next := row.State
	changes := map[string]any{}
	if p.Status != nil && *p.Status != row.State.Status {
		ok := false
		for _, s := range transitions[row.State.Status] {
			if s == *p.Status {
				ok = true
			}
		}
		if !ok {
			return IncidentDetailView{}, domain.Conflict("INVALID_STATE", "cannot move from %s to %s", row.State.Status, *p.Status)
		}
		changes["status"] = map[string]string{"from": row.State.Status, "to": *p.Status}
		next.Status = *p.Status
	}
	if p.AssigneeSet {
		changes["assignee"] = map[string]any{"from": row.State.Assignee, "to": p.Assignee}
		next.Assignee = p.Assignee
	}
	err = a.Store.InTx(ctx, func(tx Store) error {
		st, err := tx.UpdateIncidentState(ctx, next, row.State.Version, a.now())
		if err != nil {
			return err
		}
		row.State = st
		_, err = a.audit(ctx, tx, actor, "incident.updated", incidentID, changes)
		return err
	})
	if err != nil {
		return IncidentDetailView{}, err
	}
	a.notify("incident.updated", map[string]any{"incident_id": incidentID, "run_id": row.RunID})
	full, err := a.Store.GetIncident(ctx, row.RunID, incidentID)
	if err != nil {
		return IncidentDetailView{}, err
	}
	return detailView(full), nil
}

// AlertView is an alert enriched with its ATT&CK tactic and stage.
type AlertView struct {
	domain.Alert
	Tactic  *string `json:"tactic"`
	Stage   *int    `json:"stage"`
	OnChain *bool   `json:"on_chain,omitempty"`
}

func (a *App) AlertView(al domain.Alert) AlertView {
	v := AlertView{Alert: al}
	if t, ok := a.Attack.Lookup(al.TechniqueID); ok && al.TechniqueID != "" {
		tac, st := t.Tactic, t.Stage
		v.Tactic, v.Stage = &tac, &st
	}
	return v
}

func (a *App) IncidentAlerts(ctx context.Context, incidentID, runID string, onChainOnly bool) ([]AlertView, error) {
	row, err := a.GetIncident(ctx, incidentID, runID)
	if err != nil {
		return nil, err
	}
	ds, err := a.runDataset(ctx, row.RunID)
	if err != nil {
		return nil, err
	}
	alerts, err := a.Store.AlertsByID(ctx, ds, row.Incident.AlertIDs)
	if err != nil {
		return nil, err
	}
	chain := map[string]bool{}
	for _, id := range row.Incident.ChainIDs {
		chain[id] = true
	}
	out := make([]AlertView, 0, len(alerts))
	for _, al := range alerts {
		oc := chain[al.ID]
		if onChainOnly && !oc {
			continue
		}
		v := a.AlertView(al)
		v.Raw = nil
		v.OnChain = &oc
		out = append(out, v)
	}
	return out, nil
}

type CohesionView struct {
	IncidentID   string               `json:"incident_id"`
	Cohesion     string               `json:"cohesion"`
	Reason       string               `json:"reason"`
	BridgeEdges  []domain.BridgeEdge  `json:"bridge_edges"`
	SplitPreview *domain.SplitPreview `json:"split_preview"`
}

func (a *App) Cohesion(ctx context.Context, incidentID, runID string) (CohesionView, error) {
	row, err := a.GetIncident(ctx, incidentID, runID)
	if err != nil {
		return CohesionView{}, err
	}
	inc := row.Incident
	v := CohesionView{IncidentID: inc.ID, Cohesion: inc.Cohesion, Reason: inc.CohesionReason, BridgeEdges: inc.BridgeEdges}
	if v.BridgeEdges == nil {
		v.BridgeEdges = []domain.BridgeEdge{}
	}
	if inc.Cohesion == "fragile" {
		v.SplitPreview = inc.SplitPreview
	}
	return v, nil
}

// ParseWhatIf parses repeated host:criticality pairs.
func ParseWhatIf(vals []string) (map[string]int, error) {
	out := map[string]int{}
	for _, v := range vals {
		h, c, ok := strings.Cut(v, ":")
		n, err := strconv.Atoi(c)
		if !ok || err != nil || n < 1 || n > 10 || h == "" {
			return nil, domain.Validation(domain.FieldError{Field: "query.what_if_criticality", Message: "must look like dc01:4 with criticality 1–10"})
		}
		out[strings.ToLower(h)] = n
	}
	return out, nil
}

func (a *App) Counterfactuals(ctx context.Context, incidentID, runID string, whatIf map[string]int) (counterfactual.Set, error) {
	row, err := a.GetIncident(ctx, incidentID, runID)
	if err != nil {
		return counterfactual.Set{}, err
	}
	run, err := a.Store.GetRun(ctx, row.RunID)
	if err != nil {
		return counterfactual.Set{}, err
	}
	alerts, err := a.Store.AlertsByID(ctx, run.DatasetID, row.Incident.AlertIDs)
	if err != nil {
		return counterfactual.Set{}, err
	}
	assets, err := a.Store.AssetMap(ctx)
	if err != nil {
		return counterfactual.Set{}, err
	}
	prec := map[string]float64{}
	for _, r := range row.Incident.Breakdown.Rules {
		prec[r.RuleID] = r.Precision
	}
	bands := domain.Bands{}
	if run.Bands != nil {
		bands = *run.Bands
	}
	return counterfactual.Compute(counterfactual.Input{
		Incident: row.Incident, Alerts: alerts, Assets: assets, Precision: prec, Attack: a.Attack,
		Weights: row.Incident.Breakdown.Weights, Bands: bands, HasCase: row.CaseID != nil, WhatIf: whatIf,
	}), nil
}

// ---------- split ----------

type SplitResult struct {
	RunID            string          `json:"run_id"`
	SourceIncidentID string          `json:"source_incident_id"`
	Incidents        []SplitIncident `json:"incidents"`
	AuditSeq         int64           `json:"audit_seq"`
}

type SplitIncident struct {
	IncidentID string  `json:"incident_id"`
	Priority   string  `json:"priority"`
	Risk       float64 `json:"risk"`
	AlertCount int     `json:"alert_count"`
}

// SplitIncident records the analyst's judgement that a bridge link is wrong
// and materialises it as a new run. The original run stays immutable, so its
// receipt stays valid; the cut is part of the new run's config hash, and every
// later run of the dataset honours it.
func (a *App) SplitIncident(ctx context.Context, incidentID, alertA, alertB, note, actor string) (SplitResult, error) {
	runID, err := a.incidentRun(ctx, incidentID, "")
	if err != nil {
		return SplitResult{}, err
	}
	row, err := a.Store.GetIncident(ctx, runID, incidentID)
	if err != nil {
		return SplitResult{}, err
	}
	found := false
	for _, b := range row.Incident.BridgeEdges {
		if (b.AlertA == alertA && b.AlertB == alertB) || (b.AlertA == alertB && b.AlertB == alertA) {
			found = true
		}
	}
	if !found {
		return SplitResult{}, domain.Conflict("NOT_FRAGILE", "%s–%s is not a bridge of %s; refresh its cohesion", alertA, alertB, incidentID)
	}
	src, err := a.Store.GetRun(ctx, runID)
	if err != nil {
		return SplitResult{}, err
	}
	if err := a.Store.AddCut(ctx, Cut{DatasetID: src.DatasetID, AlertA: alertA, AlertB: alertB, IncidentID: incidentID,
		Note: note, CreatedBy: actor, CreatedAt: a.now()}); err != nil {
		return SplitResult{}, err
	}
	cuts, err := a.Store.ListCuts(ctx, src.DatasetID)
	if err != nil {
		return SplitResult{}, err
	}
	cfg := a.engineConfig(cuts)
	ref := &SplitRef{RunID: runID, IncidentID: incidentID, AlertA: alertA, AlertB: alertB}
	run, err := a.createRun(ctx, src.DatasetID, actor, cfg, RunParams{SplitOf: ref})
	if err != nil {
		return SplitResult{}, err
	}
	res, err := a.execute(ctx, runJob{runID: run.RunID, datasetID: src.DatasetID, actor: actor, cfg: cfg, internal: true})
	if err != nil {
		return SplitResult{}, err
	}
	out := SplitResult{RunID: run.RunID, SourceIncidentID: incidentID}
	seen := map[string]bool{}
	for _, inc := range res.incidents {
		for _, id := range inc.AlertIDs {
			if (id == alertA || id == alertB) && !seen[inc.ID] {
				seen[inc.ID] = true
				out.Incidents = append(out.Incidents, SplitIncident{inc.ID, inc.Priority, inc.Risk, len(inc.AlertIDs)})
			}
		}
	}
	e, err := a.audit(ctx, a.Store, actor, "incident.split", incidentID, map[string]any{
		"source_run_id": runID, "new_run_id": run.RunID, "bridge": map[string]string{"alert_a": alertA, "alert_b": alertB}, "note": note})
	if err != nil {
		return out, err
	}
	out.AuditSeq = e.Seq
	return out, nil
}

// ---------- feedback, rules, suppressions ----------

type FeedbackInput struct {
	Verdict  string
	Note     *string
	RunID    string
	Suppress *SuppressInput
}

type SuppressInput struct {
	RuleID    string
	EntityKey string
	ExpiresAt *time.Time
}

type FeedbackResult struct {
	Feedback         Feedback            `json:"feedback"`
	Status           string              `json:"status"`
	RuleUpdates      []RuleUpdate        `json:"rule_updates"`
	Suppression      *domain.Suppression `json:"suppression"`
	RerunRecommended bool                `json:"rerun_recommended"`
}

// RecordFeedback updates Beta(α,β) once per distinct rule in the incident,
// for every alert source. The current run's scores do not change; the UI
// offers a re-run.
func (a *App) RecordFeedback(ctx context.Context, incidentID, actor, role string, in FeedbackInput) (FeedbackResult, error) {
	if in.Suppress != nil && role != "lead" {
		return FeedbackResult{}, domain.Forbidden("suppressing a rule requires the lead role")
	}
	row, err := a.GetIncident(ctx, incidentID, in.RunID)
	if err != nil {
		return FeedbackResult{}, err
	}
	var rules []string
	for _, r := range row.Incident.Breakdown.Rules {
		rules = append(rules, r.RuleID)
	}
	var res FeedbackResult
	err = a.Store.InTx(ctx, func(tx Store) error {
		fb, err := tx.CreateFeedback(ctx, Feedback{IncidentID: incidentID, RunID: row.RunID, Verdict: in.Verdict, Note: in.Note, UserID: actor, CreatedAt: a.now()})
		if err != nil {
			return err
		}
		res.Feedback = fb
		if res.RuleUpdates, err = tx.ApplyVerdict(ctx, rules, in.Verdict == "confirmed"); err != nil {
			return err
		}
		st, err := tx.IncidentState(ctx, incidentID)
		if err != nil {
			return err
		}
		prev := st.Status
		st.Status = in.Verdict
		if st, err = tx.UpdateIncidentState(ctx, st, st.Version, a.now()); err != nil {
			return err
		}
		res.Status = st.Status
		if _, err := a.audit(ctx, tx, actor, "feedback.created", incidentID, map[string]any{
			"verdict": in.Verdict, "rules": rules, "status": map[string]string{"from": prev, "to": st.Status}}); err != nil {
			return err
		}
		if in.Suppress != nil {
			sup, err := tx.CreateSuppression(ctx, domain.Suppression{RuleID: in.Suppress.RuleID, EntityKey: in.Suppress.EntityKey,
				Reason: deref(in.Note), CreatedBy: actor, CreatedAt: a.now(), ExpiresAt: in.Suppress.ExpiresAt})
			if err != nil {
				return err
			}
			res.Suppression = &sup
			if _, err := a.audit(ctx, tx, actor, "suppression.created", incidentID, map[string]any{
				"suppression_id": sup.ID, "rule_id": sup.RuleID, "entity_key": sup.EntityKey}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return FeedbackResult{}, err
	}
	if res.RuleUpdates == nil {
		res.RuleUpdates = []RuleUpdate{}
	}
	res.RerunRecommended = true
	a.notify("incident.updated", map[string]any{"incident_id": incidentID, "run_id": row.RunID})
	return res, nil
}

type RuleView struct {
	domain.RuleStat
	Precision           float64 `json:"precision"`
	AlertsInCurrentRuns int     `json:"alerts_in_current_runs"`
}

func (a *App) Rules(ctx context.Context) ([]RuleView, error) {
	stats, err := a.Store.ListRuleStats(ctx)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	ds, err := a.Store.ListDatasets(ctx, "", 500, nil, "")
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		if d.CurrentRunID == nil || d.Kind == "adversarial" {
			continue
		}
		c, err := a.Store.RulesInRun(ctx, *d.CurrentRunID)
		if err != nil {
			return nil, err
		}
		for k, v := range c {
			counts[k] += v
		}
	}
	out := make([]RuleView, len(stats))
	for i, s := range stats {
		out[i] = RuleView{RuleStat: s, Precision: round2(s.Precision()), AlertsInCurrentRuns: counts[s.RuleID]}
	}
	return out, nil
}

func (a *App) DeleteSuppression(ctx context.Context, id int64, actor string) error {
	return a.Store.InTx(ctx, func(tx Store) error {
		if err := tx.DeleteSuppression(ctx, id); err != nil {
			return err
		}
		_, err := a.audit(ctx, tx, actor, "suppression.deleted", strconv.FormatInt(id, 10), map[string]any{"suppression_id": id})
		return err
	})
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"prahari/internal/app"
	"prahari/internal/domain"
)

// ---------- compliance ----------

func (s *Store) insertCase(ctx context.Context, c app.Case) error {
	if _, err := s.exec(ctx, `INSERT INTO compliance_cases (case_id, incident_id, dataset_id, run_id, priority, headline, detected_at, trigger, evidence_hash)
		VALUES (?,?,?,?,?,?,?,?,?)`, c.CaseID, c.IncidentID, c.DatasetID, c.RunID, c.Priority, c.Headline, s.ts(c.DetectedAt), js(c.Trigger), c.EvidenceHash); err != nil {
		return err
	}
	for _, t := range c.Tracks {
		var draft any
		if len(t.Draft) > 0 {
			draft = string(t.Draft)
		}
		if _, err := s.exec(ctx, `INSERT INTO compliance_tracks (case_id, track, deadline, status, draft, generated_at) VALUES (?,?,?,?,?,?)`,
			c.CaseID, t.Track, s.ts(t.Deadline), t.Status, draft, s.nts(t.GeneratedAt)); err != nil {
			return err
		}
	}
	return nil
}

const caseCols = `case_id, incident_id, dataset_id, run_id, priority, headline, detected_at, trigger, evidence_hash`

func scanCase(sc interface{ Scan(...any) error }) (app.Case, error) {
	var c app.Case
	err := sc.Scan(&c.CaseID, &c.IncidentID, &c.DatasetID, &c.RunID, &c.Priority, &c.Headline, tsv{&c.DetectedAt}, jsonv{&c.Trigger}, &c.EvidenceHash)
	return c, err
}

func (s *Store) tracks(ctx context.Context, caseIDs []string) (map[string][]app.Track, error) {
	out := map[string][]app.Track{}
	if len(caseIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(caseIDs))
	for i, id := range caseIDs {
		args[i] = id
	}
	rows, err := s.query(ctx, `SELECT case_id, track, deadline, status, draft, generated_at, submitted_at, submitted_by, reference, note
		FROM compliance_tracks WHERE case_id IN (`+placeholders(len(caseIDs))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t app.Track
		var by, ref, note sql.NullString
		var draft json.RawMessage
		if err := rows.Scan(&t.CaseID, &t.Track, tsv{&t.Deadline}, &t.Status, jsonv{&draft}, ntsv{&t.GeneratedAt}, ntsv{&t.SubmittedAt}, &by, &ref, &note); err != nil {
			return nil, err
		}
		t.Draft = draft
		if by.Valid {
			t.SubmittedBy = &by.String
		}
		if ref.Valid {
			t.Reference = &ref.String
		}
		if note.Valid {
			t.Note = &note.String
		}
		out[t.CaseID] = append(out[t.CaseID], t)
	}
	order := map[string]int{"certin": 0, "dpdp_intimation": 1, "dpdp_report": 2}
	for k := range out {
		ts := out[k]
		sort.Slice(ts, func(i, j int) bool { return order[ts[i].Track] < order[ts[j].Track] })
	}
	return out, rows.Err()
}

func (s *Store) cases(ctx context.Context, q string, args ...any) ([]app.Case, error) {
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var out []app.Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	ids := make([]string, len(out))
	for i, c := range out {
		ids[i] = c.CaseID
	}
	tr, err := s.tracks(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Tracks = tr[out[i].CaseID]
	}
	return out, nil
}

func (s *Store) CaseByIncident(ctx context.Context, incidentID string) (app.Case, error) {
	cs, err := s.cases(ctx, `SELECT `+caseCols+` FROM compliance_cases WHERE incident_id = ?`, incidentID)
	if err != nil {
		return app.Case{}, err
	}
	if len(cs) == 0 {
		return app.Case{}, domain.NotFound("case for incident " + incidentID)
	}
	return cs[0], nil
}

// NextCaseID numbers cases in order of creation. Cases are never deleted, so
// a count is gapless; lexical MAX would break past CASE-9999.
func (s *Store) NextCaseID(ctx context.Context) (string, error) {
	var n int
	if err := s.row(ctx, `SELECT COUNT(*) FROM compliance_cases`).Scan(&n); err != nil {
		return "", err
	}
	return fmt.Sprintf("CASE-%04d", n+1), nil
}

func (s *Store) ListCases(ctx context.Context, datasetID string) ([]app.Case, error) {
	if datasetID != "" {
		return s.cases(ctx, `SELECT `+caseCols+` FROM compliance_cases WHERE dataset_id = ? ORDER BY detected_at DESC, case_id DESC`, datasetID)
	}
	return s.cases(ctx, `SELECT `+caseCols+` FROM compliance_cases ORDER BY detected_at DESC, case_id DESC`)
}

func (s *Store) GetCase(ctx context.Context, caseID string) (app.Case, error) {
	cs, err := s.cases(ctx, `SELECT `+caseCols+` FROM compliance_cases WHERE case_id = ?`, caseID)
	if err != nil {
		return app.Case{}, err
	}
	if len(cs) == 0 {
		return app.Case{}, domain.NotFound("case " + caseID)
	}
	return cs[0], nil
}

func (s *Store) GetTrack(ctx context.Context, caseID, track string) (app.Track, error) {
	tr, err := s.tracks(ctx, []string{caseID})
	if err != nil {
		return app.Track{}, err
	}
	for _, t := range tr[caseID] {
		if t.Track == track {
			return t, nil
		}
	}
	return app.Track{}, domain.NotFound("track " + track + " on " + caseID)
}

func (s *Store) RecordSubmission(ctx context.Context, caseID, track, by, reference, note string, at time.Time) error {
	var n any
	if note != "" {
		n = note
	}
	res, err := s.exec(ctx, `UPDATE compliance_tracks SET status = 'submitted', submitted_at = ?, submitted_by = ?, reference = ?, note = ?
		WHERE case_id = ? AND track = ? AND submitted_at IS NULL`, s.ts(at), by, reference, n, caseID, track)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		if _, err := s.GetTrack(ctx, caseID, track); err != nil {
			return err
		}
		return domain.Conflict("ALREADY_SUBMITTED", "%s for %s was already submitted", track, caseID)
	}
	return nil
}

// ---------- audit ----------

// AppendAudit extends the hash chain. The UPDATE on audit_head takes a row
// lock (Postgres) or the write lock (SQLite), so concurrent appends serialise
// and seq stays gapless.
func (s *Store) AppendAudit(ctx context.Context, e app.AuditEntry) (app.AuditEntry, error) {
	err := s.tx(ctx, func(t *Store) error {
		var prev string
		if err := t.row(ctx, `UPDATE audit_head SET seq = seq + 1 WHERE id = 1 RETURNING seq, hash`).Scan(&e.Seq, &prev); err != nil {
			return err
		}
		e.TS = app.AuditTime(e.TS)
		if len(e.Payload) == 0 {
			e.Payload = json.RawMessage("{}")
		}
		subject := ""
		if e.Subject != nil {
			subject = *e.Subject
		}
		e.PrevHash = prev
		e.Hash = app.AuditHash(prev, e.TS, e.Actor, e.Action, subject, e.Payload)
		if _, err := t.exec(ctx, `INSERT INTO audit_log (seq, ts, actor, action, subject, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)`,
			e.Seq, t.ts(e.TS), e.Actor, e.Action, nstr(e.Subject), string(e.Payload), e.PrevHash, e.Hash); err != nil {
			return err
		}
		_, err := t.exec(ctx, `UPDATE audit_head SET hash = ? WHERE id = 1`, e.Hash)
		return err
	})
	return e, err
}

func scanAudit(sc interface{ Scan(...any) error }) (app.AuditEntry, error) {
	var e app.AuditEntry
	var subject sql.NullString
	err := sc.Scan(&e.Seq, tsv{&e.TS}, &e.Actor, &e.Action, &subject, jsonv{&e.Payload}, &e.PrevHash, &e.Hash)
	if subject.Valid {
		e.Subject = &subject.String
	}
	return e, err
}

func (s *Store) ListAudit(ctx context.Context, subject, action string, limit int, beforeSeq int64) ([]app.AuditEntry, error) {
	q := `SELECT seq, ts, actor, action, subject, payload, prev_hash, hash FROM audit_log WHERE 1=1`
	var args []any
	if subject != "" {
		q += ` AND subject = ?`
		args = append(args, subject)
	}
	if action != "" {
		q += ` AND action = ?`
		args = append(args, action)
	}
	if beforeSeq > 0 {
		q += ` AND seq < ?`
		args = append(args, beforeSeq)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) WalkAudit(ctx context.Context, fn func(app.AuditEntry) error) error {
	rows, err := s.query(ctx, `SELECT seq, ts, actor, action, subject, payload, prev_hash, hash FROM audit_log ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ---------- adversary ----------

const campaignCols = `campaign_id, base_dataset, strategy, budgets, mitigated, seed, status, created_by, created_at, finished_at, duration_ms, error`

func scanCampaign(sc interface{ Scan(...any) error }) (app.Campaign, error) {
	var c app.Campaign
	var dur sql.NullInt64
	var errS sql.NullString
	err := sc.Scan(&c.CampaignID, &c.BaseDataset, &c.Strategy, jsonv{&c.Budgets}, &c.Mitigated, &c.Seed, &c.Status, &c.CreatedBy,
		tsv{&c.CreatedAt}, ntsv{&c.FinishedAt}, &dur, &errS)
	if dur.Valid {
		c.DurationMS = &dur.Int64
	}
	if errS.Valid {
		c.Error = &errS.String
	}
	return c, err
}

func (s *Store) CreateCampaign(ctx context.Context, c app.Campaign) error {
	_, err := s.exec(ctx, `INSERT INTO evasion_campaigns (campaign_id, base_dataset, strategy, budgets, mitigated, seed, status, created_by, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, c.CampaignID, c.BaseDataset, c.Strategy, js(c.Budgets), c.Mitigated, c.Seed, c.Status, c.CreatedBy, s.ts(c.CreatedAt))
	return err
}

func (s *Store) UpdateCampaign(ctx context.Context, id, status string, finished *time.Time, durationMS *int64, errMsg *string) error {
	var d any
	if durationMS != nil {
		d = *durationMS
	}
	_, err := s.exec(ctx, `UPDATE evasion_campaigns SET status = ?, finished_at = COALESCE(?, finished_at), duration_ms = COALESCE(?, duration_ms),
		error = COALESCE(?, error) WHERE campaign_id = ?`, status, s.nts(finished), d, nstr(errMsg), id)
	return err
}

func (s *Store) GetCampaign(ctx context.Context, id string) (app.Campaign, error) {
	c, err := scanCampaign(s.row(ctx, `SELECT `+campaignCols+` FROM evasion_campaigns WHERE campaign_id = ?`, id))
	return c, notFound(err, "campaign "+id)
}

func (s *Store) ListCampaigns(ctx context.Context, base string, limit int, after *time.Time, afterID string) ([]app.Campaign, error) {
	q := `SELECT ` + campaignCols + ` FROM evasion_campaigns WHERE 1=1`
	var args []any
	if base != "" {
		q += ` AND base_dataset = ?`
		args = append(args, base)
	}
	if after != nil {
		q += ` AND (created_at < ? OR (created_at = ? AND campaign_id < ?))`
		args = append(args, s.ts(*after), s.ts(*after), afterID)
	}
	q += ` ORDER BY created_at DESC, campaign_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) PutEvasionResult(ctx context.Context, r app.EvasionResult) error {
	var rank any
	if r.TopRank != nil {
		rank = *r.TopRank
	}
	_, err := s.exec(ctx, `INSERT INTO evasion_results (campaign_id, budget, variant_dataset, run_id, scenario_recall, pairwise_precision,
		pairwise_recall, incidents, detected, top_rank, scenarios_evaluated) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.CampaignID, r.Budget, r.VariantDataset, r.RunID, r.ScenarioRecall, r.PairwisePrecision, r.PairwiseRecall,
		r.Incidents, r.Detected, rank, r.ScenariosEvaluated)
	return err
}

func (s *Store) EvasionResults(ctx context.Context, campaignID string) ([]app.EvasionResult, error) {
	rows, err := s.query(ctx, `SELECT campaign_id, budget, variant_dataset, run_id, scenario_recall, pairwise_precision, pairwise_recall,
		incidents, detected, top_rank, scenarios_evaluated FROM evasion_results WHERE campaign_id = ? ORDER BY budget`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.EvasionResult
	for rows.Next() {
		var r app.EvasionResult
		var rank sql.NullInt64
		if err := rows.Scan(&r.CampaignID, &r.Budget, &r.VariantDataset, &r.RunID, &r.ScenarioRecall, &r.PairwisePrecision,
			&r.PairwiseRecall, &r.Incidents, &r.Detected, &rank, &r.ScenariosEvaluated); err != nil {
			return nil, err
		}
		if rank.Valid {
			v := int(rank.Int64)
			r.TopRank = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TamperForTest attempts to rewrite an audit row. The conformance suite uses
// it to prove the append-only trigger holds on both dialects.
func (s *Store) TamperForTest(ctx context.Context) error {
	_, err := s.exec(ctx, `UPDATE audit_log SET actor = 'mallory' WHERE seq = 1`)
	return err
}

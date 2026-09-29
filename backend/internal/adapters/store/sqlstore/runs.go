package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"prahari/internal/app"
	"prahari/internal/domain"
)

// ---------- locks ----------

// TryLock takes the dataset's run lock. An expired lock is cleared first, so a
// crashed process never wedges a dataset for longer than the TTL.
func (s *Store) TryLock(ctx context.Context, datasetID, runID string, now time.Time, ttl time.Duration) (bool, string, error) {
	var ok bool
	var active string
	err := s.tx(ctx, func(t *Store) error {
		if _, err := t.exec(ctx, `DELETE FROM run_locks WHERE dataset_id = ? AND expires_at < ?`, datasetID, t.ts(now)); err != nil {
			return err
		}
		n, err := t.countRows(ctx, `INSERT INTO run_locks (dataset_id, run_id, acquired_at, expires_at) VALUES (?,?,?,?)
			ON CONFLICT (dataset_id) DO NOTHING RETURNING run_id`, datasetID, runID, t.ts(now), t.ts(now.Add(ttl)))
		if err != nil {
			return err
		}
		if n == 1 {
			ok = true
			return nil
		}
		return t.row(ctx, `SELECT run_id FROM run_locks WHERE dataset_id = ?`, datasetID).Scan(&active)
	})
	return ok, active, err
}

func (s *Store) Unlock(ctx context.Context, datasetID, runID string) error {
	_, err := s.exec(ctx, `DELETE FROM run_locks WHERE dataset_id = ? AND run_id = ?`, datasetID, runID)
	return err
}

func (s *Store) ReapStaleLocks(ctx context.Context, now time.Time) ([]app.RunLock, error) {
	var out []app.RunLock
	err := s.tx(ctx, func(t *Store) error {
		rows, err := t.query(ctx, `SELECT dataset_id, run_id, expires_at FROM run_locks WHERE expires_at < ?`, t.ts(now))
		if err != nil {
			return err
		}
		for rows.Next() {
			var l app.RunLock
			if err := rows.Scan(&l.DatasetID, &l.RunID, tsv{&l.ExpiresAt}); err != nil {
				rows.Close()
				return err
			}
			out = append(out, l)
		}
		rows.Close()
		for _, l := range out {
			if _, err := t.exec(ctx, `DELETE FROM run_locks WHERE dataset_id = ? AND run_id = ?`, l.DatasetID, l.RunID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// ---------- runs ----------

const runCols = `run_id, dataset_id, status, requested_by, params, summary, error, input_hash, config_hash, output_hash,
	engine_version, attack_version, dialect, bands, created_at, started_at, finished_at, computed_at`

func scanRun(sc interface{ Scan(...any) error }) (app.Run, error) {
	var r app.Run
	var errS, ih, ch, oh, ev, av, di sql.NullString
	var bands json.RawMessage
	err := sc.Scan(&r.RunID, &r.DatasetID, &r.Status, &r.RequestedBy, jsonv{&r.Params}, jsonv{&r.Summary}, &errS,
		&ih, &ch, &oh, &ev, &av, &di, jsonv{&bands}, tsv{&r.CreatedAt}, ntsv{&r.StartedAt}, ntsv{&r.FinishedAt}, ntsv{&r.ComputedAt})
	if errS.Valid {
		r.Error = &errS.String
	}
	r.InputHash, r.ConfigHash, r.OutputHash = ih.String, ch.String, oh.String
	r.EngineVersion, r.AttackVersion, r.Dialect = ev.String, av.String, di.String
	if len(bands) > 0 && string(bands) != "null" {
		var b domain.Bands
		if json.Unmarshal(bands, &b) == nil {
			r.Bands = &b
		}
	}
	return r, err
}

func (s *Store) CreateRun(ctx context.Context, r app.Run) error {
	_, err := s.exec(ctx, `INSERT INTO runs (run_id, dataset_id, status, requested_by, params, created_at) VALUES (?,?,?,?,?,?)`,
		r.RunID, r.DatasetID, r.Status, r.RequestedBy, rawOr(r.Params, "{}"), s.ts(r.CreatedAt))
	return err
}

func (s *Store) GetRun(ctx context.Context, runID string) (app.Run, error) {
	r, err := scanRun(s.row(ctx, `SELECT `+runCols+` FROM runs WHERE run_id = ?`, runID))
	return r, notFound(err, "run "+runID)
}

func (s *Store) ListRuns(ctx context.Context, datasetID string, limit int, after *time.Time, afterID string) ([]app.Run, error) {
	q := `SELECT ` + runCols + ` FROM runs WHERE 1=1`
	var args []any
	if datasetID != "" {
		q += ` AND dataset_id = ?`
		args = append(args, datasetID)
	}
	if after != nil {
		q += ` AND (created_at < ? OR (created_at = ? AND run_id < ?))`
		args = append(args, s.ts(*after), s.ts(*after), afterID)
	}
	q += ` ORDER BY created_at DESC, run_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) StartRun(ctx context.Context, runID string, at time.Time) error {
	_, err := s.exec(ctx, `UPDATE runs SET status = 'running', started_at = ? WHERE run_id = ? AND status = 'queued'`, s.ts(at), runID)
	return err
}

func (s *Store) FailRun(ctx context.Context, runID, status, reason string, at time.Time) error {
	_, err := s.exec(ctx, `UPDATE runs SET status = ?, error = ?, finished_at = ? WHERE run_id = ? AND status IN ('queued', 'running')`,
		status, reason, s.ts(at), runID)
	return err
}

// CommitRun writes a finished run in one transaction: run row, incidents,
// memberships, analyst-state rows for new incident IDs, compliance cases and
// the current-run pointer.
func (s *Store) CommitRun(ctx context.Context, set app.CommitSet) error {
	return s.tx(ctx, func(t *Store) error {
		r := set.Run
		var bands any
		if r.Bands != nil {
			bands = js(r.Bands)
		}
		res, err := t.exec(ctx, `UPDATE runs SET status = 'succeeded', summary = ?, params = ?, input_hash = ?, config_hash = ?, output_hash = ?,
			engine_version = ?, attack_version = ?, dialect = ?, bands = ?, finished_at = ?, computed_at = ?, started_at = COALESCE(started_at, ?)
			WHERE run_id = ?`,
			rawOr(r.Summary, "null"), rawOr(r.Params, "{}"), r.InputHash, r.ConfigHash, r.OutputHash, r.EngineVersion, r.AttackVersion,
			r.Dialect, bands, t.nts(r.FinishedAt), t.nts(r.ComputedAt), t.nts(r.StartedAt), r.RunID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errors.New("commit: run row missing")
		}
		now := time.Now()
		if r.FinishedAt != nil {
			now = *r.FinishedAt
		}
		for start := 0; start < len(set.Incidents); start += 100 {
			batch := set.Incidents[start:min(start+100, len(set.Incidents))]
			var b strings.Builder
			b.WriteString(`INSERT INTO incidents (run_id, id, rank, label, headline, risk, priority, cohesion, max_stage, first_seen, last_seen, alert_count, has_breach, summary, detail, facts_hash) VALUES `)
			var args []any
			for i, inc := range batch {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
				sum := inc
				sum.Graph, sum.Timeline = domain.Graph{}, domain.Timeline{}
				args = append(args, r.RunID, inc.ID, inc.Rank, inc.Label, inc.Headline, inc.Risk, inc.Priority, inc.Cohesion, inc.MaxStage,
					t.ts(inc.FirstSeen), t.ts(inc.LastSeen), len(inc.AlertIDs), inc.Breach != nil, js(sum), js(inc), set.FactsHash[inc.ID])
			}
			if _, err := t.exec(ctx, b.String(), args...); err != nil {
				return err
			}
		}
		type member struct {
			inc, alert string
			chain      bool
		}
		var ms []member
		for _, inc := range set.Incidents {
			chain := map[string]bool{}
			for _, id := range inc.ChainIDs {
				chain[id] = true
			}
			for _, a := range inc.AlertIDs {
				ms = append(ms, member{inc.ID, a, chain[a]})
			}
		}
		for start := 0; start < len(ms); start += insertChunk {
			batch := ms[start:min(start+insertChunk, len(ms))]
			var b strings.Builder
			b.WriteString(`INSERT INTO incident_alerts (run_id, incident_id, alert_id, on_chain) VALUES `)
			args := make([]any, 0, len(batch)*4)
			for i, m := range batch {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`(?,?,?,?)`)
				args = append(args, r.RunID, m.inc, m.alert, m.chain)
			}
			if _, err := t.exec(ctx, b.String(), args...); err != nil {
				return err
			}
		}
		for start := 0; start < len(set.Incidents); start += insertChunk {
			batch := set.Incidents[start:min(start+insertChunk, len(set.Incidents))]
			var b strings.Builder
			b.WriteString(`INSERT INTO incident_state (incident_id, status, version, updated_at) VALUES `)
			var args []any
			for i, inc := range batch {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`(?, 'open', 1, ?)`)
				args = append(args, inc.ID, t.ts(now))
			}
			b.WriteString(` ON CONFLICT (incident_id) DO NOTHING`)
			if _, err := t.exec(ctx, b.String(), args...); err != nil {
				return err
			}
		}
		for _, c := range set.Cases {
			if err := t.insertCase(ctx, c); err != nil {
				return err
			}
		}
		if set.SetCurrent {
			return t.SetCurrentRun(ctx, r.DatasetID, r.RunID)
		}
		return nil
	})
}

// ---------- incidents ----------

func (s *Store) ListIncidents(ctx context.Context, runID string) ([]app.IncidentRow, error) {
	rows, err := s.query(ctx, `SELECT i.summary, st.status, st.assignee, st.version, st.updated_at, c.case_id
		FROM incidents i
		LEFT JOIN incident_state st ON st.incident_id = i.id
		LEFT JOIN compliance_cases c ON c.incident_id = i.id
		WHERE i.run_id = ? ORDER BY i.rank`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.IncidentRow
	for rows.Next() {
		r, err := scanIncidentRow(rows, runID)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanIncidentRow(sc interface{ Scan(...any) error }, runID string) (app.IncidentRow, error) {
	r := app.IncidentRow{RunID: runID}
	var status sql.NullString
	var assignee, caseID sql.NullString
	var version sql.NullInt64
	var updated time.Time
	err := sc.Scan(jsonv{&r.Incident}, &status, &assignee, &version, tsv{&updated}, &caseID)
	r.State = app.IncidentState{IncidentID: r.Incident.ID, Status: "open", Version: 1, UpdatedAt: updated}
	if status.Valid {
		r.State.Status = status.String
		r.State.Version = int(version.Int64)
	}
	if assignee.Valid {
		r.State.Assignee = &assignee.String
	}
	if caseID.Valid {
		r.CaseID = &caseID.String
	}
	return r, err
}

func (s *Store) GetIncident(ctx context.Context, runID, incidentID string) (app.IncidentRow, error) {
	r, err := scanIncidentRow(s.row(ctx, `SELECT i.detail, st.status, st.assignee, st.version, st.updated_at, c.case_id
		FROM incidents i
		LEFT JOIN incident_state st ON st.incident_id = i.id
		LEFT JOIN compliance_cases c ON c.incident_id = i.id
		WHERE i.run_id = ? AND i.id = ?`, runID, incidentID), runID)
	return r, notFound(err, "incident "+incidentID)
}

func (s *Store) IncidentState(ctx context.Context, incidentID string) (app.IncidentState, error) {
	st := app.IncidentState{IncidentID: incidentID}
	var assignee sql.NullString
	err := s.row(ctx, `SELECT status, assignee, version, updated_at FROM incident_state WHERE incident_id = ?`, incidentID).
		Scan(&st.Status, &assignee, &st.Version, tsv{&st.UpdatedAt})
	if assignee.Valid {
		st.Assignee = &assignee.String
	}
	return st, notFound(err, "incident "+incidentID)
}

// UpdateIncidentState is optimistic: it succeeds only if the version still
// matches, which is what backs If-Match.
func (s *Store) UpdateIncidentState(ctx context.Context, st app.IncidentState, expect int, at time.Time) (app.IncidentState, error) {
	res, err := s.exec(ctx, `UPDATE incident_state SET status = ?, assignee = ?, version = version + 1, updated_at = ?
		WHERE incident_id = ? AND version = ?`, st.Status, nstr(st.Assignee), s.ts(at), st.IncidentID, expect)
	if err != nil {
		return st, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.IncidentState(ctx, st.IncidentID); err != nil {
			return st, err
		}
		return st, domain.E(412, "PRECONDITION_FAILED", "incident %s changed since you read it", st.IncidentID)
	}
	return s.IncidentState(ctx, st.IncidentID)
}

func (s *Store) RulesInRun(ctx context.Context, runID string) (map[string]int, error) {
	rows, err := s.query(ctx, `SELECT a.rule_id, COUNT(*) FROM incident_alerts ia
		JOIN runs r ON r.run_id = ia.run_id
		JOIN alerts a ON a.dataset_id = r.dataset_id AND a.id = ia.alert_id
		WHERE ia.run_id = ? GROUP BY a.rule_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

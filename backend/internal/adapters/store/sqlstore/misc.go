package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"prahari/internal/app"
	"prahari/internal/domain"
)

// ---------- users ----------

func (s *Store) UserByUsername(ctx context.Context, username string) (app.User, error) {
	var u app.User
	err := s.row(ctx, `SELECT user_id, username, display_name, role, password_hash FROM users WHERE username = ?`, username).
		Scan(&u.UserID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash)
	return u, notFound(err, "user")
}

func (s *Store) UserByID(ctx context.Context, id string) (app.User, error) {
	var u app.User
	err := s.row(ctx, `SELECT user_id, username, display_name, role, password_hash FROM users WHERE user_id = ?`, id).
		Scan(&u.UserID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash)
	return u, notFound(err, "user")
}

func (s *Store) UpsertUser(ctx context.Context, u app.User) error {
	_, err := s.exec(ctx, `INSERT INTO users (user_id, username, display_name, role, password_hash) VALUES (?,?,?,?,?)
		ON CONFLICT (user_id) DO UPDATE SET username = excluded.username, display_name = excluded.display_name,
		role = excluded.role, password_hash = excluded.password_hash`, u.UserID, u.Username, u.DisplayName, u.Role, u.PasswordHash)
	return err
}

// ---------- assets ----------

func scanAsset(sc interface{ Scan(...any) error }) (domain.Asset, error) {
	var a domain.Asset
	var owner sql.NullString
	err := sc.Scan(&a.Hostname, &a.Role, &a.Criticality, jsonv{&a.DataClasses}, &owner, tsv{&a.UpdatedAt})
	a.Owner = owner.String
	if a.DataClasses == nil {
		a.DataClasses = []string{}
	}
	return a, err
}

func (s *Store) ListAssets(ctx context.Context, minCrit int, dataClass string) ([]domain.Asset, error) {
	rows, err := s.query(ctx, `SELECT hostname, role, criticality, data_classes, owner, updated_at FROM assets
		WHERE criticality >= ? ORDER BY criticality DESC, hostname`, minCrit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		if dataClass != "" && !contains(a.DataClasses, dataClass) {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAsset(ctx context.Context, hostname string) (domain.Asset, error) {
	a, err := scanAsset(s.row(ctx, `SELECT hostname, role, criticality, data_classes, owner, updated_at FROM assets WHERE hostname = ?`, hostname))
	return a, notFound(err, "asset "+hostname)
}

func (s *Store) UpsertAsset(ctx context.Context, a domain.Asset) (bool, error) {
	created := false
	err := s.tx(ctx, func(t *Store) error {
		var n int
		if err := t.row(ctx, `SELECT COUNT(*) FROM assets WHERE hostname = ?`, a.Hostname).Scan(&n); err != nil {
			return err
		}
		created = n == 0
		if a.DataClasses == nil {
			a.DataClasses = []string{}
		}
		var owner any
		if a.Owner != "" {
			owner = a.Owner
		}
		_, err := t.exec(ctx, `INSERT INTO assets (hostname, role, criticality, data_classes, owner, updated_at) VALUES (?,?,?,?,?,?)
			ON CONFLICT (hostname) DO UPDATE SET role = excluded.role, criticality = excluded.criticality,
			data_classes = excluded.data_classes, owner = excluded.owner, updated_at = excluded.updated_at`,
			a.Hostname, a.Role, a.Criticality, js(a.DataClasses), owner, t.ts(a.UpdatedAt))
		return err
	})
	return created, err
}

func (s *Store) AssetMap(ctx context.Context) (map[string]domain.Asset, error) {
	as, err := s.ListAssets(ctx, 0, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]domain.Asset, len(as))
	for _, a := range as {
		out[a.Hostname] = a
	}
	return out, nil
}

// ---------- narratives ----------

func (s *Store) GetNarrative(ctx context.Context, factsHash string) (app.StoredNarrative, error) {
	var n app.StoredNarrative
	var model sql.NullString
	err := s.row(ctx, `SELECT facts_hash, incident_id, source, model, attempts, body, validation, generated_at FROM narratives WHERE facts_hash = ?`, factsHash).
		Scan(&n.FactsHash, &n.IncidentID, &n.Source, &model, &n.Attempts, jsonv{&n.Body}, jsonv{&n.Validation}, tsv{&n.GeneratedAt})
	if model.Valid {
		n.Model = &model.String
	}
	return n, notFound(err, "narrative")
}

func (s *Store) PutNarrative(ctx context.Context, n app.StoredNarrative) error {
	_, err := s.exec(ctx, `INSERT INTO narratives (facts_hash, incident_id, source, model, attempts, body, validation, generated_at) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT (facts_hash) DO UPDATE SET source = excluded.source, model = excluded.model, attempts = excluded.attempts,
		body = excluded.body, validation = excluded.validation, generated_at = excluded.generated_at`,
		n.FactsHash, n.IncidentID, n.Source, nstr(n.Model), n.Attempts, rawOr(n.Body, "{}"), rawOr(n.Validation, "{}"), s.ts(n.GeneratedAt))
	return err
}

// ---------- rule learning ----------

func (s *Store) ListRuleStats(ctx context.Context) ([]domain.RuleStat, error) {
	rows, err := s.query(ctx, `SELECT rule_id, rule_name, source, technique_id, alpha, beta, confirmed, false_positives FROM rule_stats ORDER BY rule_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RuleStat
	for rows.Next() {
		var r domain.RuleStat
		if err := rows.Scan(&r.RuleID, &r.RuleName, &r.Source, &r.TechniqueID, &r.Alpha, &r.Beta, &r.Confirmed, &r.FalsePositives); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RuleStatMap(ctx context.Context) (map[string]domain.RuleStat, error) {
	rs, err := s.ListRuleStats(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]domain.RuleStat, len(rs))
	for _, r := range rs {
		out[r.RuleID] = r
	}
	return out, nil
}

func (s *Store) SeedRuleStats(ctx context.Context, stats []domain.RuleStat) error {
	return s.tx(ctx, func(t *Store) error {
		for _, r := range stats {
			if _, err := t.exec(ctx, `INSERT INTO rule_stats (rule_id, rule_name, source, technique_id, alpha, beta) VALUES (?,?,?,?,?,?)
				ON CONFLICT (rule_id) DO NOTHING`, r.RuleID, r.RuleName, r.Source, r.TechniqueID, r.Alpha, r.Beta); err != nil {
				return err
			}
		}
		return nil
	})
}

// ApplyVerdict adds one to α (confirmed) or β (false positive) for each
// distinct rule. A rule never seen before starts from Beta(1,1).
func (s *Store) ApplyVerdict(ctx context.Context, ruleIDs []string, confirmed bool) ([]app.RuleUpdate, error) {
	ids := append([]string(nil), ruleIDs...)
	sort.Strings(ids)
	var out []app.RuleUpdate
	err := s.tx(ctx, func(t *Store) error {
		for i, id := range ids {
			if i > 0 && ids[i-1] == id {
				continue
			}
			// normally registered at ingest; this covers a verdict racing ingest
			if _, err := t.exec(ctx, `INSERT INTO rule_stats (rule_id, rule_name, source, alpha, beta) VALUES (?, ?, 'edr', 1, 1)
				ON CONFLICT (rule_id) DO NOTHING`, id, id); err != nil {
				return err
			}
			var a, b float64
			if err := t.row(ctx, `SELECT alpha, beta FROM rule_stats WHERE rule_id = ?`, id).Scan(&a, &b); err != nil {
				return err
			}
			u := app.RuleUpdate{RuleID: id, PrecisionBefore: round2(a / (a + b))}
			q := `UPDATE rule_stats SET beta = beta + 1, false_positives = false_positives + 1 WHERE rule_id = ?`
			if confirmed {
				q = `UPDATE rule_stats SET alpha = alpha + 1, confirmed = confirmed + 1 WHERE rule_id = ?`
				a++
			} else {
				b++
			}
			if _, err := t.exec(ctx, q, id); err != nil {
				return err
			}
			u.Alpha, u.Beta, u.PrecisionAfter = a, b, round2(a/(a+b))
			out = append(out, u)
		}
		return nil
	})
	return out, err
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

func scanSuppression(sc interface{ Scan(...any) error }) (domain.Suppression, error) {
	var x domain.Suppression
	var reason sql.NullString
	err := sc.Scan(&x.ID, &x.RuleID, &x.EntityKey, &reason, &x.CreatedBy, tsv{&x.CreatedAt}, ntsv{&x.ExpiresAt})
	x.Reason = reason.String
	return x, err
}

func (s *Store) ListSuppressions(ctx context.Context) ([]domain.Suppression, error) {
	rows, err := s.query(ctx, `SELECT suppression_id, rule_id, entity_key, reason, created_by, created_at, expires_at FROM suppressions ORDER BY suppression_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Suppression
	for rows.Next() {
		x, err := scanSuppression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) CreateSuppression(ctx context.Context, x domain.Suppression) (domain.Suppression, error) {
	var reason any
	if x.Reason != "" {
		reason = x.Reason
	}
	rows, err := s.query(ctx, `INSERT INTO suppressions (rule_id, entity_key, reason, created_by, created_at, expires_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT (rule_id, entity_key) DO NOTHING RETURNING suppression_id`,
		x.RuleID, x.EntityKey, reason, x.CreatedBy, s.ts(x.CreatedAt), s.nts(x.ExpiresAt))
	if err != nil {
		return x, err
	}
	defer rows.Close()
	if !rows.Next() {
		return x, domain.Conflict("ALREADY_EXISTS", "a suppression for %s on %s already exists", x.RuleID, x.EntityKey)
	}
	if err := rows.Scan(&x.ID); err != nil {
		return x, err
	}
	return x, nil
}

func (s *Store) DeleteSuppression(ctx context.Context, id int64) error {
	res, err := s.exec(ctx, `DELETE FROM suppressions WHERE suppression_id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.NotFound("suppression")
	}
	return nil
}

func (s *Store) CreateFeedback(ctx context.Context, f app.Feedback) (app.Feedback, error) {
	err := s.row(ctx, `INSERT INTO feedback (incident_id, run_id, verdict, note, user_id, created_at) VALUES (?,?,?,?,?,?) RETURNING feedback_id`,
		f.IncidentID, f.RunID, f.Verdict, nstr(f.Note), f.UserID, s.ts(f.CreatedAt)).Scan(&f.FeedbackID)
	return f, err
}

func (s *Store) ListFeedback(ctx context.Context, incidentID string) ([]app.Feedback, error) {
	rows, err := s.query(ctx, `SELECT feedback_id, incident_id, run_id, verdict, note, user_id, created_at FROM feedback
		WHERE incident_id = ? ORDER BY created_at DESC, feedback_id DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Feedback
	for rows.Next() {
		var f app.Feedback
		var note sql.NullString
		if err := rows.Scan(&f.FeedbackID, &f.IncidentID, &f.RunID, &f.Verdict, &note, &f.UserID, tsv{&f.CreatedAt}); err != nil {
			return nil, err
		}
		if note.Valid {
			f.Note = &note.String
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) AddCut(ctx context.Context, c app.Cut) error {
	a, b := c.AlertA, c.AlertB
	if a > b {
		a, b = b, a
	}
	_, err := s.exec(ctx, `INSERT INTO dataset_cuts (dataset_id, alert_a, alert_b, incident_id, note, created_by, created_at) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT (dataset_id, alert_a, alert_b) DO NOTHING`, c.DatasetID, a, b, c.IncidentID, c.Note, c.CreatedBy, s.ts(c.CreatedAt))
	return err
}

func (s *Store) ListCuts(ctx context.Context, datasetID string) ([]app.Cut, error) {
	rows, err := s.query(ctx, `SELECT dataset_id, alert_a, alert_b, incident_id, note, created_by, created_at FROM dataset_cuts
		WHERE dataset_id = ? ORDER BY alert_a, alert_b`, datasetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Cut
	for rows.Next() {
		var c app.Cut
		if err := rows.Scan(&c.DatasetID, &c.AlertA, &c.AlertB, &c.IncidentID, &c.Note, &c.CreatedBy, tsv{&c.CreatedAt}); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- evaluations and idempotency ----------

func (s *Store) PutEvaluation(ctx context.Context, e app.Evaluation) error {
	_, err := s.exec(ctx, `INSERT INTO evaluations (evaluation_id, run_id, dataset_id, created_at, body) VALUES (?,?,?,?,?)`,
		e.EvaluationID, e.RunID, e.DatasetID, s.ts(e.CreatedAt), string(e.Body))
	return err
}

func (s *Store) LatestEvaluation(ctx context.Context, datasetID string) (app.Evaluation, error) {
	var e app.Evaluation
	err := s.row(ctx, `SELECT evaluation_id, run_id, dataset_id, created_at, body FROM evaluations WHERE dataset_id = ?
		ORDER BY created_at DESC, evaluation_id DESC LIMIT 1`, datasetID).
		Scan(&e.EvaluationID, &e.RunID, &e.DatasetID, tsv{&e.CreatedAt}, jsonv{&e.Body})
	return e, notFound(err, "evaluation")
}

func (s *Store) PutTruth(ctx context.Context, datasetID string, body []byte, at time.Time) error {
	_, err := s.exec(ctx, `INSERT INTO ground_truths (dataset_id, created_at, body) VALUES (?,?,?)
		ON CONFLICT (dataset_id) DO UPDATE SET created_at = excluded.created_at, body = excluded.body`,
		datasetID, s.ts(at), string(body))
	return err
}

func (s *Store) GetTruth(ctx context.Context, datasetID string) ([]byte, error) {
	var b json.RawMessage
	err := s.row(ctx, `SELECT body FROM ground_truths WHERE dataset_id = ?`, datasetID).Scan(jsonv{&b})
	return b, notFound(err, "ground truth")
}

func (s *Store) GetIdempotent(ctx context.Context, userID, route, key string, since time.Time) (app.IdempotentResponse, bool, error) {
	var r app.IdempotentResponse
	var headers json.RawMessage
	err := s.row(ctx, `SELECT body_hash, status, headers, body FROM idempotency_keys WHERE user_id = ? AND route = ? AND key = ? AND created_at >= ?`,
		userID, route, key, s.ts(since)).Scan(&r.BodyHash, &r.Status, jsonv{&headers}, &r.Body)
	if err == sql.ErrNoRows {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	_ = json.Unmarshal(headers, &r.Headers)
	return r, true, nil
}

func (s *Store) PutIdempotent(ctx context.Context, userID, route, key string, r app.IdempotentResponse, at time.Time) error {
	if r.Headers == nil {
		r.Headers = map[string]string{}
	}
	_, err := s.exec(ctx, `INSERT INTO idempotency_keys (user_id, route, key, body_hash, status, headers, body, created_at) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT (user_id, route, key) DO UPDATE SET body_hash = excluded.body_hash, status = excluded.status,
		headers = excluded.headers, body = excluded.body, created_at = excluded.created_at`,
		userID, route, key, r.BodyHash, r.Status, js(r.Headers), string(r.Body), s.ts(at))
	return err
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

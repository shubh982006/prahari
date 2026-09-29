package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"prahari/internal/app"
	"prahari/internal/core/entity"
	"prahari/internal/domain"
)

// ---------- datasets ----------

const datasetCols = `dataset_id, kind, seed, window_start, window_end, scenarios, has_truth, parent_id, current_run_id, auth_events, alerts, alerts_by_detector, created_at`

func scanDataset(sc interface{ Scan(...any) error }) (app.Dataset, error) {
	var d app.Dataset
	var seed sql.NullInt64
	var parent, current sql.NullString
	err := sc.Scan(&d.DatasetID, &d.Kind, &seed, tsv{&d.WindowStart}, tsv{&d.WindowEnd}, jsonv{&d.Scenarios},
		&d.HasTruth, &parent, &current, &d.AuthEvents, &d.Alerts, &d.AlertsByDetector, tsv{&d.CreatedAt})
	if seed.Valid {
		d.Seed = &seed.Int64
	}
	if parent.Valid {
		d.ParentID = &parent.String
	}
	if current.Valid {
		d.CurrentRunID = &current.String
	}
	if d.Scenarios == nil {
		d.Scenarios = []string{}
	}
	return d, err
}

func (s *Store) CreateDataset(ctx context.Context, d app.Dataset) error {
	if d.Scenarios == nil {
		d.Scenarios = []string{}
	}
	_, err := s.exec(ctx, `INSERT INTO datasets (`+datasetCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		d.DatasetID, d.Kind, d.Seed, s.ts(d.WindowStart), s.ts(d.WindowEnd), js(d.Scenarios), d.HasTruth,
		nstr(d.ParentID), nstr(d.CurrentRunID), d.AuthEvents, d.Alerts, d.AlertsByDetector, s.ts(d.CreatedAt))
	if err != nil && isUnique(err) {
		return domain.Conflict("ALREADY_EXISTS", "dataset %s already exists", d.DatasetID)
	}
	return err
}

func (s *Store) GetDataset(ctx context.Context, id string) (app.Dataset, error) {
	d, err := scanDataset(s.row(ctx, `SELECT `+datasetCols+` FROM datasets WHERE dataset_id = ?`, id))
	return d, notFound(err, "dataset "+id)
}

func (s *Store) ListDatasets(ctx context.Context, kind string, limit int, after *time.Time, afterID string) ([]app.Dataset, error) {
	q := `SELECT ` + datasetCols + ` FROM datasets WHERE 1=1`
	var args []any
	if kind != "" {
		q += ` AND kind = ?`
		args = append(args, kind)
	}
	if after != nil {
		q += ` AND (created_at < ? OR (created_at = ? AND dataset_id < ?))`
		args = append(args, s.ts(*after), s.ts(*after), afterID)
	}
	q += ` ORDER BY created_at DESC, dataset_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.Dataset
	for rows.Next() {
		d, err := scanDataset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) AddDatasetCounts(ctx context.Context, id string, authEvents, alerts, detector int) error {
	_, err := s.exec(ctx, `UPDATE datasets SET auth_events = auth_events + ?, alerts = alerts + ?, alerts_by_detector = alerts_by_detector + ? WHERE dataset_id = ?`,
		authEvents, alerts, detector, id)
	return err
}

func (s *Store) ExtendDatasetWindow(ctx context.Context, id string, from, to time.Time) error {
	_, err := s.exec(ctx, `UPDATE datasets SET
		window_start = CASE WHEN window_start > ? THEN ? ELSE window_start END,
		window_end   = CASE WHEN window_end   < ? THEN ? ELSE window_end END
		WHERE dataset_id = ?`, s.ts(from), s.ts(from), s.ts(to), s.ts(to), id)
	return err
}

func (s *Store) SetCurrentRun(ctx context.Context, datasetID, runID string) error {
	_, err := s.exec(ctx, `UPDATE datasets SET current_run_id = ? WHERE dataset_id = ?`, runID, datasetID)
	return err
}

// ---------- partitions (Postgres) ----------

// ensurePartitions creates the monthly partitions a batch needs. DDL runs on
// the pool, outside any transaction, so concurrent ingests do not deadlock on
// the catalog; "already exists" is expected under races and ignored.
func (s *Store) ensurePartitions(ctx context.Context, tables []string, times []time.Time) error {
	if !s.pg() {
		return nil
	}
	months := map[time.Time]bool{}
	for _, t := range times {
		t = t.UTC()
		months[time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)] = true
	}
	for m := range months {
		for _, table := range tables {
			name := fmt.Sprintf("%s_%04d_%02d", table, m.Year(), int(m.Month()))
			if _, ok := s.parts.Load(name); ok {
				continue
			}
			q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
				name, table, m.Format(time.RFC3339), m.AddDate(0, 1, 0).Format(time.RFC3339))
			if _, err := s.db.ExecContext(ctx, q); err != nil && !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("partition %s: %w", name, err)
			}
			s.parts.Store(name, true)
		}
	}
	return nil
}

// ---------- ingest ----------

const insertChunk = 400

func (s *Store) InsertAuthEvents(ctx context.Context, events []domain.AuthEvent) (int, int, error) {
	if len(events) == 0 {
		return 0, 0, nil
	}
	times := make([]time.Time, len(events))
	for i, e := range events {
		times[i] = e.TS
	}
	if err := s.ensurePartitions(ctx, []string{"auth_events"}, times); err != nil {
		return 0, 0, err
	}
	inserted := 0
	for start := 0; start < len(events); start += insertChunk {
		batch := events[start:min(start+insertChunk, len(events))]
		var b strings.Builder
		b.WriteString(`INSERT INTO auth_events (dataset_id, event_id, ts, username, src_ip, geo, result, app, is_admin) VALUES `)
		args := make([]any, 0, len(batch)*9)
		for i, e := range batch {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`(?,?,?,?,?,?,?,?,?)`)
			args = append(args, e.DatasetID, e.EventID, s.ts(e.TS), e.Username, e.SrcIP, e.Geo, e.Result, e.App, e.IsAdmin)
		}
		b.WriteString(` ON CONFLICT DO NOTHING RETURNING event_id`)
		n, err := s.countRows(ctx, b.String(), args...)
		if err != nil {
			return inserted, 0, err
		}
		inserted += n
	}
	return inserted, len(events) - inserted, nil
}

func (s *Store) countRows(ctx context.Context, q string, args ...any) (int, error) {
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}

func (s *Store) AuthEventsBetween(ctx context.Context, datasetID string, from, to time.Time) ([]domain.AuthEvent, error) {
	rows, err := s.query(ctx, `SELECT event_id, ts, username, src_ip, geo, result, app, is_admin FROM auth_events
		WHERE dataset_id = ? AND ts >= ? AND ts < ? ORDER BY ts, event_id`, datasetID, s.ts(from), s.ts(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuthEvent
	for rows.Next() {
		e := domain.AuthEvent{DatasetID: datasetID}
		if err := rows.Scan(&e.EventID, tsv{&e.TS}, &e.Username, &e.SrcIP, &e.Geo, &e.Result, &e.App, &e.IsAdmin); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertAlerts writes alerts and their entity index rows. Duplicates on
// (dataset_id, id, ts) are counted and ignored, which makes re-ingest
// idempotent.
func (s *Store) InsertAlerts(ctx context.Context, alerts []domain.Alert) (int, int, error) {
	if len(alerts) == 0 {
		return 0, 0, nil
	}
	times := make([]time.Time, len(alerts))
	for i, a := range alerts {
		times[i] = a.TS
	}
	if err := s.ensurePartitions(ctx, []string{"alerts", "alert_entities"}, times); err != nil {
		return 0, 0, err
	}
	inserted := 0
	err := s.tx(ctx, func(t *Store) error {
		for start := 0; start < len(alerts); start += insertChunk {
			batch := alerts[start:min(start+insertChunk, len(alerts))]
			var b strings.Builder
			b.WriteString(`INSERT INTO alerts (dataset_id, id, ts, source, rule_id, rule_name, severity, technique_id, entities, raw) VALUES `)
			args := make([]any, 0, len(batch)*10)
			byID := make(map[string]*domain.Alert, len(batch))
			for i := range batch {
				a := &batch[i]
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`(?,?,?,?,?,?,?,?,?,?)`)
				raw := rawOr(a.Raw, "{}")
				args = append(args, a.DatasetID, a.ID, t.ts(a.TS), a.Source, a.RuleID, a.RuleName, string(a.Severity), a.TechniqueID, js(a.Entities.Normalized()), raw)
				byID[a.ID] = a
			}
			b.WriteString(` ON CONFLICT DO NOTHING RETURNING id`)
			rows, err := t.query(ctx, b.String(), args...)
			if err != nil {
				return err
			}
			var fresh []*domain.Alert
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				fresh = append(fresh, byID[id])
			}
			rows.Close()
			inserted += len(fresh)
			if err := t.insertEntities(ctx, fresh); err != nil {
				return err
			}
		}
		return nil
	})
	return inserted, len(alerts) - inserted, err
}

func (s *Store) insertEntities(ctx context.Context, alerts []*domain.Alert) error {
	type row struct {
		ds, key, id string
		ts          time.Time
	}
	var rs []row
	for _, a := range alerts {
		for _, k := range entity.Keys(a.Entities) {
			rs = append(rs, row{a.DatasetID, k, a.ID, a.TS})
		}
	}
	for start := 0; start < len(rs); start += insertChunk {
		batch := rs[start:min(start+insertChunk, len(rs))]
		var b strings.Builder
		b.WriteString(`INSERT INTO alert_entities (dataset_id, entity_key, alert_id, ts) VALUES `)
		args := make([]any, 0, len(batch)*4)
		for i, r := range batch {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`(?,?,?,?)`)
			args = append(args, r.ds, r.key, r.id, s.ts(r.ts))
		}
		b.WriteString(` ON CONFLICT DO NOTHING`)
		if _, err := s.exec(ctx, b.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

// ---------- alerts ----------

const alertCols = `dataset_id, id, ts, source, rule_id, rule_name, severity, technique_id, entities, raw`

func scanAlert(sc interface{ Scan(...any) error }) (domain.Alert, error) {
	var a domain.Alert
	var sev string
	var raw json.RawMessage
	err := sc.Scan(&a.DatasetID, &a.ID, tsv{&a.TS}, &a.Source, &a.RuleID, &a.RuleName, &sev, &a.TechniqueID, jsonv{&a.Entities}, jsonv{&raw})
	a.Severity = domain.Severity(sev)
	a.Entities = a.Entities.Normalized()
	a.Raw = raw
	return a, err
}

func (s *Store) alerts(ctx context.Context, q string, args ...any) ([]domain.Alert, error) {
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ListAlerts(ctx context.Context, f app.AlertFilter) ([]domain.Alert, error) {
	q := `SELECT ` + alertCols + ` FROM alerts WHERE dataset_id = ?`
	args := []any{f.DatasetID}
	if f.From != nil {
		q += ` AND ts >= ?`
		args = append(args, s.ts(*f.From))
	}
	if f.To != nil {
		q += ` AND ts < ?`
		args = append(args, s.ts(*f.To))
	}
	if len(f.Sources) > 0 {
		q += ` AND source IN (` + placeholders(len(f.Sources)) + `)`
		for _, x := range f.Sources {
			args = append(args, x)
		}
	}
	if len(f.Severity) > 0 {
		q += ` AND severity IN (` + placeholders(len(f.Severity)) + `)`
		for _, x := range f.Severity {
			args = append(args, x)
		}
	}
	if f.RuleID != "" {
		q += ` AND rule_id = ?`
		args = append(args, f.RuleID)
	}
	if f.Entity != "" {
		q += ` AND id IN (SELECT alert_id FROM alert_entities WHERE dataset_id = ? AND entity_key = ?)`
		args = append(args, f.DatasetID, f.Entity)
	}
	if f.Q != "" {
		q += ` AND LOWER(rule_name) LIKE ?`
		args = append(args, "%"+strings.ToLower(f.Q)+"%")
	}
	op, dir := ">", "ASC"
	if f.Desc {
		op, dir = "<", "DESC"
	}
	if f.After != nil {
		q += ` AND (ts ` + op + ` ? OR (ts = ? AND id ` + op + ` ?))`
		args = append(args, s.ts(f.After.TS), s.ts(f.After.TS), f.After.ID)
	}
	q += ` ORDER BY ts ` + dir + `, id ` + dir + ` LIMIT ?`
	args = append(args, f.Limit)
	return s.alerts(ctx, q, args...)
}

func (s *Store) AlertStats(ctx context.Context, datasetID string) (app.AlertStats, error) {
	st := app.AlertStats{BySource: map[string]int{}, BySeverity: map[string]int{}, ByHour: []app.HourCount{}}
	rows, err := s.query(ctx, `SELECT source, severity, COUNT(*) FROM alerts WHERE dataset_id = ? GROUP BY source, severity`, datasetID)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var src, sev string
		var n int
		if err := rows.Scan(&src, &sev, &n); err != nil {
			rows.Close()
			return st, err
		}
		st.BySource[src] += n
		st.BySeverity[sev] += n
		st.Total += n
	}
	rows.Close()
	hour := `substr(ts, 1, 13)`
	if s.pg() {
		hour = `to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24')`
	}
	rows, err = s.query(ctx, `SELECT `+hour+` AS h, COUNT(*) FROM alerts WHERE dataset_id = ? GROUP BY h ORDER BY h`, datasetID)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		var n int
		if err := rows.Scan(&h, &n); err != nil {
			return st, err
		}
		t, err := time.Parse("2006-01-02T15", h)
		if err != nil {
			return st, err
		}
		st.ByHour = append(st.ByHour, app.HourCount{Hour: t, Count: n})
	}
	return st, rows.Err()
}

func (s *Store) GetAlert(ctx context.Context, datasetID, id string) (domain.Alert, error) {
	a, err := scanAlert(s.row(ctx, `SELECT `+alertCols+` FROM alerts WHERE dataset_id = ? AND id = ? LIMIT 1`, datasetID, id))
	return a, notFound(err, "alert "+id)
}

func (s *Store) LoadAlerts(ctx context.Context, datasetID string) ([]domain.Alert, error) {
	return s.alerts(ctx, `SELECT `+alertCols+` FROM alerts WHERE dataset_id = ? ORDER BY ts, id`, datasetID)
}

func (s *Store) AlertsByID(ctx context.Context, datasetID string, ids []string) ([]domain.Alert, error) {
	var out []domain.Alert
	for start := 0; start < len(ids); start += 500 {
		batch := ids[start:min(start+500, len(ids))]
		args := []any{datasetID}
		for _, id := range batch {
			args = append(args, id)
		}
		as, err := s.alerts(ctx, `SELECT `+alertCols+` FROM alerts WHERE dataset_id = ? AND id IN (`+placeholders(len(batch))+`)`, args...)
		if err != nil {
			return nil, err
		}
		out = append(out, as...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// EntityEdges is consecutive-pair linking as one window function over the
// linking index, identical SQL on both dialects. The window comparison happens
// here rather than in SQL because interval arithmetic is the one thing the
// dialects disagree on. Stop-listed entities are filtered by the caller:
// dropping an entity drops exactly its partition of edges, so the result is
// the same as filtering in SQL.
func (s *Store) EntityEdges(ctx context.Context, datasetID string, window time.Duration) ([]domain.Edge, error) {
	rows, err := s.query(ctx, `SELECT entity_key, prev_id, alert_id, prev_ts, ts FROM (
		SELECT entity_key, alert_id, ts,
		       LAG(alert_id) OVER w AS prev_id,
		       LAG(ts) OVER w AS prev_ts
		FROM alert_entities
		WHERE dataset_id = ?
		WINDOW w AS (PARTITION BY entity_key ORDER BY ts, alert_id)
	) pairs WHERE prev_id IS NOT NULL ORDER BY entity_key, ts, alert_id`, datasetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Edge
	for rows.Next() {
		var key, a, b string
		var ta, tb time.Time
		if err := rows.Scan(&key, &a, &b, tsv{&ta}, tsv{&tb}); err != nil {
			return nil, err
		}
		if tb.Sub(ta) <= window {
			out = append(out, domain.Edge{A: a, B: b, EntityKey: key})
		}
	}
	return out, rows.Err()
}

func isUnique(err error) bool {
	m := err.Error()
	return strings.Contains(m, "UNIQUE constraint") || strings.Contains(m, "duplicate key") || strings.Contains(m, "SQLSTATE 23505")
}

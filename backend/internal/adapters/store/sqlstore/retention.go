package sqlstore

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"prahari/internal/app"
)

// RetentionDays is the CERT-In log retention period.
const RetentionDays = 180

var logTables = []string{"alerts", "alert_entities", "auth_events"}

var boundRe = regexp.MustCompile(`FROM \('([^']+)'\) TO \('([^']+)'\)`)

type partition struct {
	table, name string
	from, to    time.Time
}

func (s *Store) partitions(ctx context.Context) ([]partition, error) {
	rows, err := s.query(ctx, `SELECT p.relname, c.relname, pg_get_expr(c.relpartbound, c.oid)
		FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname IN ('alerts', 'alert_entities', 'auth_events')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []partition
	for rows.Next() {
		var p partition
		var bound string
		if err := rows.Scan(&p.table, &p.name, &bound); err != nil {
			return nil, err
		}
		m := boundRe.FindStringSubmatch(bound)
		if m == nil {
			continue
		}
		p.from, err = parsePGBound(m[1])
		if err != nil {
			return nil, err
		}
		p.to, err = parsePGBound(m[2])
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func parsePGBound(v string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05-07", "2006-01-02 15:04:05Z07:00", time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable partition bound %q", v)
}

// DropExpired removes log data older than before. Postgres drops whole
// partitions; SQLite deletes by timestamp and reclaims pages incrementally.
func (s *Store) DropExpired(ctx context.Context, before time.Time) (int64, error) {
	if s.pg() {
		parts, err := s.partitions(ctx)
		if err != nil {
			return 0, err
		}
		var n int64
		for _, p := range parts {
			if p.to.After(before) {
				continue
			}
			var rows int64
			if err := s.row(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, p.name)).Scan(&rows); err != nil {
				return n, err
			}
			if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`DROP TABLE %s`, p.name)); err != nil {
				return n, err
			}
			s.parts.Delete(p.name)
			n += rows
		}
		return n, nil
	}
	var n int64
	for _, t := range logTables {
		res, err := s.exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE ts < ?`, t), s.ts(before))
		if err != nil {
			return n, err
		}
		k, _ := res.RowsAffected()
		n += k
	}
	if n > 0 {
		_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	}
	return n, nil
}

// RetentionInventory lists storage units: partitions on Postgres, month
// buckets on SQLite.
func (s *Store) RetentionInventory(ctx context.Context) ([]app.RetentionUnit, string, error) {
	var out []app.RetentionUnit
	if s.pg() {
		parts, err := s.partitions(ctx)
		if err != nil {
			return nil, "", err
		}
		for _, p := range parts {
			var rows int64
			if err := s.row(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, p.name)).Scan(&rows); err != nil {
				return nil, "", err
			}
			out = append(out, app.RetentionUnit{Table: p.table, Name: p.name, From: p.from, To: p.to, Rows: rows,
				DropAfter: p.to.AddDate(0, 0, RetentionDays)})
		}
		sortUnits(out)
		return out, "partition_drop", nil
	}
	for _, t := range logTables {
		rows, err := s.query(ctx, fmt.Sprintf(`SELECT substr(ts, 1, 7) AS m, COUNT(*) FROM %s GROUP BY m ORDER BY m`, t))
		if err != nil {
			return nil, "", err
		}
		for rows.Next() {
			var m string
			var n int64
			if err := rows.Scan(&m, &n); err != nil {
				rows.Close()
				return nil, "", err
			}
			from, err := time.Parse("2006-01", m)
			if err != nil {
				rows.Close()
				return nil, "", err
			}
			to := from.AddDate(0, 1, 0)
			out = append(out, app.RetentionUnit{Table: t, Name: fmt.Sprintf("%s_%s", t, from.Format("2006_01")), From: from, To: to,
				Rows: n, DropAfter: to.AddDate(0, 0, RetentionDays)})
		}
		rows.Close()
	}
	sortUnits(out)
	return out, "delete_by_timestamp", nil
}

func sortUnits(us []app.RetentionUnit) {
	sort.Slice(us, func(i, j int) bool {
		if !us[i].From.Equal(us[j].From) {
			return us[i].From.Before(us[j].From)
		}
		return us[i].Table < us[j].Table
	})
}

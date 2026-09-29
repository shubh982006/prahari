package sqlstore

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"prahari/migrations"
)

type migration struct {
	version int
	name    string
	sql     string
}

func (s *Store) migrations() ([]migration, error) {
	dir := s.dialect
	entries, err := fs.ReadDir(migrations.FS, dir)
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("migration %s: bad version", name)
		}
		b, err := fs.ReadFile(migrations.FS, dir+"/"+name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{v, name, string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies pending migrations, each in its own transaction. It is
// idempotent.
func (s *Store) Migrate(ctx context.Context) (applied []string, err error) {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return nil, err
	}
	ms, err := s.migrations()
	if err != nil {
		return nil, err
	}
	done := map[int]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		done[v] = true
	}
	rows.Close()
	for _, m := range ms {
		if done[m.version] {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return applied, err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return applied, fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`),
			m.version, m.name, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return applied, err
		}
		if err := tx.Commit(); err != nil {
			return applied, err
		}
		applied = append(applied, m.name)
	}
	return applied, nil
}

// MigrationsCurrent reports whether every embedded migration is applied, for
// /readyz.
func (s *Store) MigrationsCurrent(ctx context.Context) (bool, error) {
	ms, err := s.migrations()
	if err != nil {
		return false, err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		return false, err
	}
	return n == len(ms), nil
}

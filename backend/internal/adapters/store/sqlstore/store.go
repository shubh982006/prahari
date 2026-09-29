// Package sqlstore implements app.Store for Postgres and SQLite. One code
// path, written in SQL valid in both dialects; the few places that must differ
// (placeholders, time encoding, partitions, retention) are isolated here and
// in retention.go. Nothing outside this package knows which dialect is live.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"prahari/internal/app"
	"prahari/internal/domain"
)

const (
	Postgres = "postgres"
	SQLite   = "sqlite"
	// sqliteTime is fixed width so TEXT timestamps sort chronologically.
	sqliteTime = "2006-01-02T15:04:05.000000Z"
)

var memSeq atomic.Int64

type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type Store struct {
	db      *sql.DB
	q       querier
	dialect string
	inTx    bool
	parts   *sync.Map // Postgres partitions known to exist
}

var _ app.Store = (*Store)(nil)

// Open infers the dialect from the DSN: postgres:// or postgresql:// is
// Postgres, anything else is a SQLite path (file:x.db, x.db, :memory:).
func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(16)
		db.SetMaxIdleConns(8)
		db.SetConnMaxIdleTime(5 * time.Minute)
		s := &Store{db: db, q: db, dialect: Postgres, parts: &sync.Map{}}
		return s, s.Ping(ctx)
	}
	path, memory := sqlitePath(dsn)
	pragmas := "_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	if !memory {
		pragmas += "&_pragma=journal_mode(WAL)"
	}
	full := "file:" + path + "?" + pragmas
	if memory {
		full = "file:" + path + "?mode=memory&cache=shared&" + pragmas
	}
	db, err := sql.Open("sqlite", full)
	if err != nil {
		return nil, err
	}
	if memory {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(8)
	}
	// Must precede table creation to take effect; harmless afterwards.
	if _, err := db.ExecContext(ctx, "PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
		return nil, err
	}
	s := &Store{db: db, q: db, dialect: SQLite, parts: &sync.Map{}}
	return s, s.Ping(ctx)
}

func sqlitePath(dsn string) (string, bool) {
	d := strings.TrimPrefix(strings.TrimPrefix(dsn, "sqlite://"), "file:")
	if i := strings.IndexByte(d, '?'); i >= 0 {
		d = d[:i]
	}
	if d == "" || d == ":memory:" {
		// each in-memory store is its own database
		return fmt.Sprintf("prahari-mem-%d", memSeq.Add(1)), true
	}
	if u, err := url.PathUnescape(d); err == nil {
		d = u
	}
	return d, false
}

func (s *Store) Dialect() string { return s.dialect }
func (s *Store) pg() bool        { return s.dialect == Postgres }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func (s *Store) Close() error                   { return s.db.Close() }

// DB exposes the pool for the migrator and pgnotify.
func (s *Store) DB() *sql.DB { return s.db }

// InTx runs fn in one transaction; nested calls join the outer one.
func (s *Store) InTx(ctx context.Context, fn func(tx app.Store) error) error {
	if s.inTx {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	ts := &Store{db: s.db, q: tx, dialect: s.dialect, inTx: true, parts: s.parts}
	if err := fn(ts); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) tx(ctx context.Context, fn func(*Store) error) error {
	return s.InTx(ctx, func(t app.Store) error { return fn(t.(*Store)) })
}

// ---------- dialect helpers ----------

// rebind turns ? placeholders into $n for Postgres. Queries in this package
// never contain a literal question mark.
func (s *Store) rebind(q string) string {
	if !s.pg() {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.q.ExecContext(ctx, s.rebind(q), args...)
}

func (s *Store) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.q.QueryContext(ctx, s.rebind(q), args...)
}

func (s *Store) row(ctx context.Context, q string, args ...any) *sql.Row {
	return s.q.QueryRowContext(ctx, s.rebind(q), args...)
}

// ts encodes a time for this dialect, at microsecond precision on both.
func (s *Store) ts(t time.Time) any {
	t = t.UTC().Truncate(time.Microsecond)
	if s.pg() {
		return t
	}
	return t.Format(sqliteTime)
}

func (s *Store) nts(t *time.Time) any {
	if t == nil {
		return nil
	}
	return s.ts(*t)
}

// tsv scans either a time.Time (Postgres) or TEXT (SQLite).
type tsv struct{ t *time.Time }

func (v tsv) Scan(src any) error {
	switch x := src.(type) {
	case time.Time:
		*v.t = x.UTC()
	case string:
		return v.parse(x)
	case []byte:
		return v.parse(string(x))
	case nil:
		*v.t = time.Time{}
	default:
		return fmt.Errorf("sqlstore: cannot scan %T into time", src)
	}
	return nil
}

func (v tsv) parse(x string) error {
	t, err := time.Parse(time.RFC3339Nano, x)
	if err != nil {
		return err
	}
	*v.t = t.UTC()
	return nil
}

// ntsv scans a nullable time.
type ntsv struct{ t **time.Time }

func (v ntsv) Scan(src any) error {
	if src == nil {
		*v.t = nil
		return nil
	}
	var t time.Time
	if err := (tsv{&t}).Scan(src); err != nil {
		return err
	}
	*v.t = &t
	return nil
}

// jsonv scans JSON stored as JSONB or TEXT.
type jsonv struct{ dst any }

func (v jsonv) Scan(src any) error {
	var b []byte
	switch x := src.(type) {
	case nil:
		return nil
	case string:
		b = []byte(x)
	case []byte:
		b = x
	default:
		return fmt.Errorf("sqlstore: cannot scan %T into json", src)
	}
	if raw, ok := v.dst.(*json.RawMessage); ok {
		*raw = append(json.RawMessage(nil), b...)
		return nil
	}
	return json.Unmarshal(b, v.dst)
}

func js(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func rawOr(b json.RawMessage, def string) string {
	if len(b) == 0 {
		return def
	}
	return string(b)
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func notFound(err error, what string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NotFound(what)
	}
	return err
}

func nstr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

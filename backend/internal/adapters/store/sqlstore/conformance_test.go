package sqlstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"prahari/internal/adapters/store/conformance"
	"prahari/internal/adapters/store/sqlstore"
	"prahari/internal/app"
)

func NewSQLite(t testing.TB) *sqlstore.Store {
	t.Helper()
	s, err := sqlstore.Open(context.Background(), filepath.Join(t.TempDir(), "prahari.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var pgSeq atomic.Int64

// NewPostgres creates a throwaway database from PRAHARI_TEST_PG (an admin DSN,
// e.g. postgres://me@localhost:5432/postgres?sslmode=disable) and drops it
// when the test ends. Tests skip when the variable is unset.
func NewPostgres(t testing.TB) *sqlstore.Store {
	t.Helper()
	admin := os.Getenv("PRAHARI_TEST_PG")
	if admin == "" {
		t.Skip("PRAHARI_TEST_PG not set")
	}
	name := fmt.Sprintf("prahari_test_%d_%d", time.Now().UnixNano()%1e9, pgSeq.Add(1))
	adb, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adb.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	dsn := strings.Replace(admin, "/postgres?", "/"+name+"?", 1)
	s, err := sqlstore.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		_, _ = adb.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		adb.Close()
	})
	return s
}

func TestConformanceSQLite(t *testing.T) {
	conformance.RunSuite(t, func(t *testing.T) app.Store { return NewSQLite(t) })
}

func TestConformancePostgres(t *testing.T) {
	conformance.RunSuite(t, func(t *testing.T) app.Store { return NewPostgres(t) })
}

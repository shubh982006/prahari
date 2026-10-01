package app_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"prahari/internal/adapters/broker/inproc"
	"prahari/internal/adapters/clock"
	"prahari/internal/adapters/llm/azureopenai"
	"prahari/internal/adapters/store/sqlstore"
	"prahari/internal/app"
	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/evaluate"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

var t0 = time.Date(2026, 9, 29, 7, 0, 0, 0, time.UTC)

func sqlite(t *testing.T) *sqlstore.Store {
	s, err := sqlstore.Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
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

func postgres(t *testing.T) *sqlstore.Store {
	admin := os.Getenv("PRAHARI_TEST_PG")
	if admin == "" {
		t.Skip("PRAHARI_TEST_PG not set")
	}
	name := fmt.Sprintf("prahari_app_%d_%d", time.Now().UnixNano()%1e9, pgSeq.Add(1))
	adb, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adb.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatal(err)
	}
	s, err := sqlstore.Open(context.Background(), strings.Replace(admin, "/postgres?", "/"+name+"?", 1))
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

func newApp(t *testing.T, s app.Store) *app.App {
	cat, err := attack.LoadFile("../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		t.Fatal(err)
	}
	a := app.New(app.Deps{Store: s, Pub: inproc.New(), LLM: azureopenai.Disabled{}, Clock: clock.NewFixed(t0),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Attack: cat, Engine: correlate.DefaultConfig(),
		DataDir: t.TempDir(), Version: "test", JWTSecret: []byte("0123456789abcdef0123456789abcdef")})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { a.Stop(context.Background()); cancel() })
	if err := a.Setup(ctx, "lead-pw", "analyst-pw"); err != nil {
		t.Fatal(err)
	}
	a.Start(ctx)
	return a
}

// runAndWait queues a run and waits for it to finish.
func runAndWait(t *testing.T, a *app.App, ds string) app.Run {
	t.Helper()
	r, err := a.StartRun(context.Background(), ds, "u_meow", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		got, _ := a.Store.GetRun(context.Background(), r.RunID)
		switch got.Status {
		case "succeeded":
			return got
		case "failed", "cancelled":
			t.Fatalf("run %s: %v", got.Status, *got.Error)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return app.Run{}
}

func receipts(t *testing.T, s app.Store) app.Receipt {
	a := newApp(t, s)
	d, err := a.Simulate(context.Background(), simulate.Params{Seed: 7}, "u_meow")
	if err != nil {
		t.Fatal(err)
	}
	r := runAndWait(t, a, d.DatasetID)
	rc, err := a.GetReceipt(context.Background(), r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

// The same seed through both stores must produce byte-identical hashes. If
// this fails, determinism is a lie.
func TestReceiptIdenticalAcrossDialects(t *testing.T) {
	a := receipts(t, sqlite(t))
	b := receipts(t, sqlite(t)) // a second, independent database
	if a.InputHash != b.InputHash || a.ConfigHash != b.ConfigHash || a.OutputHash != b.OutputHash {
		t.Fatalf("two SQLite runs disagree:\n%+v\n%+v", a, b)
	}
	if os.Getenv("PRAHARI_TEST_PG") == "" {
		t.Skip("Postgres half skipped: PRAHARI_TEST_PG not set")
	}
	p := receipts(t, postgres(t))
	if a.InputHash != p.InputHash || a.ConfigHash != p.ConfigHash || a.OutputHash != p.OutputHash {
		t.Fatalf("SQLite and Postgres disagree:\nsqlite   %s %s %s\npostgres %s %s %s",
			a.InputHash, a.ConfigHash, a.OutputHash, p.InputHash, p.ConfigHash, p.OutputHash)
	}
	if a.Dialect != "sqlite" || p.Dialect != "postgres" {
		t.Fatal("dialect field")
	}
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	a := newApp(t, sqlite(t))
	d, err := a.Simulate(ctx, simulate.Params{Seed: 42}, "u_meow")
	if err != nil {
		t.Fatal(err)
	}
	if d.AuthEvents == 0 || d.Alerts == 0 || d.AlertsByDetector == 0 {
		t.Fatalf("simulation ingest counts: %+v", d)
	}
	if _, err := a.Simulate(ctx, simulate.Params{Seed: 42}, "u_meow"); !isCode(err, "ALREADY_EXISTS") {
		t.Fatalf("same seed twice: %v", err)
	}
	first := runAndWait(t, a, d.DatasetID)
	cases, _, _ := a.ListCases(ctx, "", "all")
	if len(cases) == 0 {
		t.Fatal("seed 42 should open at least one compliance case")
	}
	detected := map[string]time.Time{}
	for _, c := range cases {
		detected[c.CaseID] = c.DetectedAt
	}
	list, err := a.ListIncidents(ctx, app.IncidentFilter{DatasetID: d.DatasetID, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	top := list.Data[0]
	etag := app.IncidentETag(top.IncidentID, 1)
	st := "investigating"
	if _, err := a.PatchIncident(ctx, top.IncidentID, "", etag, "u_meow", app.IncidentPatch{Status: &st}); err != nil {
		t.Fatal(err)
	}

	// a re-run later: the clock must not move and the verdict must survive
	a.Clock.(*clock.Fixed).Advance(3 * time.Hour)
	second := runAndWait(t, a, d.DatasetID)
	if first.RunID == second.RunID {
		t.Fatal("expected a new run")
	}
	cases2, _, _ := a.ListCases(ctx, "", "all")
	if len(cases2) != len(cases) {
		t.Fatalf("re-run opened duplicate cases: %d → %d", len(cases), len(cases2))
	}
	for _, c := range cases2 {
		if !c.DetectedAt.Equal(detected[c.CaseID]) {
			t.Fatalf("%s detected_at moved on re-run: %s → %s", c.CaseID, detected[c.CaseID], c.DetectedAt)
		}
	}
	again, err := a.IncidentDetail(ctx, top.IncidentID, second.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != "investigating" {
		t.Fatalf("analyst state lost on re-run: %s", again.Status)
	}
	rc1, _ := a.GetReceipt(ctx, first.RunID)
	rc2, _ := a.GetReceipt(ctx, second.RunID)
	if rc1.OutputHash != rc2.OutputHash {
		t.Fatal("same input, same config: the output hash must repeat")
	}
	v, err := a.VerifyAudit(ctx)
	if err != nil || !v.OK {
		t.Fatalf("audit chain: %+v %v", v, err)
	}
}

func TestRunExclusivity(t *testing.T) {
	ctx := context.Background()
	a := newApp(t, sqlite(t))
	d, err := a.Simulate(ctx, simulate.Params{Seed: 3, Users: 20, NoiseLevel: "low"}, "u_meow")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := a.Store.TryLock(ctx, d.DatasetID, "someone-else", t0, time.Minute); !ok {
		t.Fatal("setup lock")
	}
	_, err = a.StartRun(ctx, d.DatasetID, "u_meow", nil)
	de, ok := domain.AsError(err)
	if !ok || de.Code != "RUN_IN_PROGRESS" || de.ActiveRunID != "someone-else" {
		t.Fatalf("want RUN_IN_PROGRESS naming the active run, got %v", err)
	}
}

func TestFeedbackLearnsForTheNextRunOnly(t *testing.T) {
	ctx := context.Background()
	a := newApp(t, sqlite(t))
	d, _ := a.Simulate(ctx, simulate.Params{Seed: 42}, "u_meow")
	runAndWait(t, a, d.DatasetID)
	list, _ := a.ListIncidents(ctx, app.IncidentFilter{DatasetID: d.DatasetID, Limit: 3})
	inc := list.Data[0]
	before, _ := a.IncidentDetail(ctx, inc.IncidentID, "")
	if _, err := a.RecordFeedback(ctx, inc.IncidentID, "u_analyst", "analyst", app.FeedbackInput{Verdict: "false_positive",
		Suppress: &app.SuppressInput{RuleID: "R", EntityKey: "ip:1.1.1.1"}}); !isCode(err, "FORBIDDEN") {
		t.Fatalf("an analyst must not suppress: %v", err)
	}
	res, err := a.RecordFeedback(ctx, inc.IncidentID, "u_analyst", "analyst", app.FeedbackInput{Verdict: "false_positive"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RuleUpdates) != len(before.Breakdown.Rules) || !res.RerunRecommended {
		t.Fatalf("one update per distinct rule: %+v", res)
	}
	for _, u := range res.RuleUpdates {
		if u.PrecisionAfter >= u.PrecisionBefore {
			t.Fatalf("a false positive must lower precision: %+v", u)
		}
	}
	after, _ := a.IncidentDetail(ctx, inc.IncidentID, "")
	if after.Risk != before.Risk {
		t.Fatal("feedback must not rescore a committed run")
	}
}

func TestSplitMaterialisesANewRun(t *testing.T) {
	ctx := context.Background()
	a := newApp(t, sqlite(t))
	d, _ := a.Simulate(ctx, simulate.Params{Seed: 42}, "u_meow")
	first := runAndWait(t, a, d.DatasetID)
	list, _ := a.ListIncidents(ctx, app.IncidentFilter{DatasetID: d.DatasetID, Cohesion: []string{"fragile"}, Limit: 50})
	if len(list.Data) == 0 {
		t.Skip("no fragile incident on this seed")
	}
	coh, _ := a.Cohesion(ctx, list.Data[0].IncidentID, "")
	b := coh.BridgeEdges[0]
	if _, err := a.SplitIncident(ctx, list.Data[0].IncidentID, "nope", "nope", "", "u_meow"); !isCode(err, "NOT_FRAGILE") {
		t.Fatalf("non-bridge: %v", err)
	}
	res, err := a.SplitIncident(ctx, list.Data[0].IncidentID, b.AlertA, b.AlertB, "unrelated", "u_meow")
	if err != nil {
		t.Fatal(err)
	}
	if res.RunID == first.RunID || len(res.Incidents) != 2 {
		t.Fatalf("split result: %+v", res)
	}
	old, _ := a.GetReceipt(ctx, first.RunID)
	neu, _ := a.GetReceipt(ctx, res.RunID)
	if old.ConfigHash == neu.ConfigHash || old.OutputHash == neu.OutputHash {
		t.Fatal("the cut must be part of the new run's config and change its output")
	}
	// the cut persists: the next ordinary run honours it
	next := runAndWait(t, a, d.DatasetID)
	rc, _ := a.GetReceipt(ctx, next.RunID)
	if rc.OutputHash != neu.OutputHash {
		t.Fatal("a later run must honour the recorded cut")
	}
}

func isCode(err error, code string) bool {
	de, ok := domain.AsError(err)
	return ok && de.Code == code
}

// A fresh demo must open with measured numbers: an evaluation and a curve for
// every strategy with and without the laundering pass. Seeding again adds nothing.
func TestSeedDemoPrewarmsEvaluationAndBench(t *testing.T) {
	if testing.Short() {
		t.Skip("runs eight adversary campaigns")
	}
	a := newApp(t, sqlite(t))
	ctx := context.Background()
	if err := a.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	ds := simulate.DatasetID(simulate.Params{Seed: 42})
	if _, err := a.LatestEvaluation(ctx, ds); err != nil {
		t.Fatalf("no evaluation after seeding: %v", err)
	}
	count := func() int {
		cs, err := a.Store.ListCampaigns(ctx, ds, 500, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, c := range cs {
			if c.Status != "succeeded" {
				t.Fatalf("campaign %s %s is %s", c.Strategy, c.CampaignID, c.Status)
			}
			n++
		}
		return n
	}
	if n := count(); n != 8 {
		t.Fatalf("want 8 campaigns (4 strategies x laundering on/off), got %d", n)
	}
	if err := a.SeedDemo(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 8 {
		t.Fatalf("second seed ran campaigns again: %d", n)
	}
	if v, err := a.VerifyAudit(ctx); err != nil || !v.OK {
		t.Fatalf("audit chain after demo: %+v err=%v", v, err)
	}
}

// Hosts like Render wipe local disk on every restart. Ground truth lives in the
// database, so evaluation still works after the data directory is gone.
func TestTruthSurvivesWipedDisk(t *testing.T) {
	for name, store := range map[string]func(*testing.T) *sqlstore.Store{"sqlite": sqlite, "postgres": postgres} {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, store(t))
			ctx := context.Background()
			ds, err := a.Simulate(ctx, simulate.Params{Seed: 3}, "u_meow")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(a.DataDir); err != nil {
				t.Fatal(err)
			}
			run := runAndWait(t, a, ds.DatasetID)
			ev, err := a.Evaluate(ctx, run.RunID, evaluate.AnalystModel{}, "u_meow")
			if err != nil {
				t.Fatalf("evaluate after the data directory was wiped: %v", err)
			}
			if len(ev.Scenarios) == 0 || string(ev.Scenarios) == "[]" {
				t.Fatal("evaluation has no scenarios")
			}
		})
	}
}

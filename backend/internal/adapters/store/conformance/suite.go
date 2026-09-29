// Package conformance is one test suite run against every Store adapter. It
// is what turns "we support both dialects" from a claim into a fact.
package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"prahari/internal/app"
	"prahari/internal/core/entity"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

var t0 = time.Date(2026, 9, 29, 3, 0, 0, 0, time.UTC)

func dataset(t *testing.T, s app.Store, id string) {
	t.Helper()
	err := s.CreateDataset(context.Background(), app.Dataset{DatasetID: id, Kind: "ingested", WindowStart: t0, WindowEnd: t0.Add(24 * time.Hour), CreatedAt: t0})
	if err != nil {
		t.Fatal(err)
	}
}

func alert(ds, id string, ts time.Time, users ...string) domain.Alert {
	return domain.Alert{DatasetID: ds, ID: id, TS: ts, Source: "edr", RuleID: "EDR-X", RuleName: "Test rule", Severity: domain.SevHigh,
		TechniqueID: "T1059.001", Entities: domain.Entities{Users: users, Hosts: []string{"ws-1"}}.Normalized(), Raw: json.RawMessage(`{"k":1}`)}
}

// RunSuite runs every conformance test against stores made by newStore. Each
// call to newStore must return an empty, migrated store.
func RunSuite(t *testing.T, newStore func(t *testing.T) app.Store) {
	ctx := context.Background()

	t.Run("AlertBatchIsIdempotent", func(t *testing.T) {
		s := newStore(t)
		dataset(t, s, "ds_idem")
		as := []domain.Alert{alert("ds_idem", "A1", t0, "a"), alert("ds_idem", "A2", t0.Add(time.Minute), "b")}
		ins, dup, err := s.InsertAlerts(ctx, as)
		if err != nil || ins != 2 || dup != 0 {
			t.Fatalf("first insert: %d %d %v", ins, dup, err)
		}
		ins, dup, err = s.InsertAlerts(ctx, as)
		if err != nil || ins != 0 || dup != 2 {
			t.Fatalf("second insert: %d %d %v", ins, dup, err)
		}
		got, err := s.LoadAlerts(ctx, "ds_idem")
		if err != nil || len(got) != 2 {
			t.Fatalf("load: %d %v", len(got), err)
		}
		if !got[0].TS.Equal(t0) || got[0].Entities.Users[0] != "a" || string(got[0].Raw) == "" {
			t.Fatalf("round trip lost data: %+v", got[0])
		}
	})

	t.Run("EntityEdgesMatchNaivePairs", func(t *testing.T) {
		s := newStore(t)
		sim := simulate.Generate(simulate.Params{Seed: 7, Users: 20, NoiseLevel: "low"})
		ds := sim.DatasetID
		dataset(t, s, ds)
		all := sim.All()
		if _, _, err := s.InsertAlerts(ctx, all); err != nil {
			t.Fatal(err)
		}
		w := 2 * time.Hour
		edges, err := s.EntityEdges(ctx, ds, w)
		if err != nil {
			t.Fatal(err)
		}
		consecutive := components(all, func(link func(a, b string)) {
			for _, e := range edges {
				link(e.A, e.B)
			}
		})
		naive := components(all, func(link func(a, b string)) {
			by := map[string][]domain.Alert{}
			for _, a := range all {
				for _, k := range entity.Keys(a.Entities) {
					by[k] = append(by[k], a)
				}
			}
			for _, xs := range by {
				for i := range xs {
					for j := i + 1; j < len(xs); j++ {
						d := xs[i].TS.Sub(xs[j].TS)
						if d < 0 {
							d = -d
						}
						if d <= w {
							link(xs[i].ID, xs[j].ID)
						}
					}
				}
			}
		})
		if consecutive != naive {
			t.Fatal("consecutive-pair linking produced different components from all-pairs linking")
		}
	})

	t.Run("RunLockIsExclusive", func(t *testing.T) {
		s := newStore(t)
		dataset(t, s, "ds_lock")
		ok, _, err := s.TryLock(ctx, "ds_lock", "r1", t0, time.Minute)
		if err != nil || !ok {
			t.Fatalf("first lock: %v %v", ok, err)
		}
		ok, active, err := s.TryLock(ctx, "ds_lock", "r2", t0, time.Minute)
		if err != nil || ok || active != "r1" {
			t.Fatalf("second lock should fail with r1 active: %v %q %v", ok, active, err)
		}
		if err := s.Unlock(ctx, "ds_lock", "r1"); err != nil {
			t.Fatal(err)
		}
		ok, _, err = s.TryLock(ctx, "ds_lock", "r2", t0, time.Minute)
		if err != nil || !ok {
			t.Fatalf("lock after unlock: %v %v", ok, err)
		}
	})

	t.Run("StaleLockIsReaped", func(t *testing.T) {
		s := newStore(t)
		dataset(t, s, "ds_stale")
		if ok, _, err := s.TryLock(ctx, "ds_stale", "dead", t0, time.Second); err != nil || !ok {
			t.Fatal(err)
		}
		reaped, err := s.ReapStaleLocks(ctx, t0.Add(time.Minute))
		if err != nil || len(reaped) != 1 || reaped[0].RunID != "dead" {
			t.Fatalf("reap: %+v %v", reaped, err)
		}
		if ok, _, err := s.TryLock(ctx, "ds_stale", "next", t0.Add(time.Minute), time.Second); err != nil || !ok {
			t.Fatalf("lock after reap: %v %v", ok, err)
		}
	})

	t.Run("CommitIsAtomic", func(t *testing.T) {
		s := newStore(t)
		dataset(t, s, "ds_commit")
		run := app.Run{RunID: "run-1", DatasetID: "ds_commit", Status: "running", RequestedBy: "u", CreatedAt: t0}
		if err := s.CreateRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		inc := domain.Incident{ID: "INC-00000001", Rank: 1, Label: "single", Priority: "P3", Cohesion: "solid",
			FirstSeen: t0, LastSeen: t0, AlertIDs: []string{"A1"}}
		fin := t0.Add(time.Second)
		run.FinishedAt = &fin
		// the duplicate incident ID violates the primary key half-way through
		err := s.CommitRun(ctx, app.CommitSet{Run: run, Incidents: []domain.Incident{inc, inc}, SetCurrent: true})
		if err == nil {
			t.Fatal("expected the duplicate incident to fail the commit")
		}
		got, _ := s.GetRun(ctx, "run-1")
		rows, _ := s.ListIncidents(ctx, "run-1")
		d, _ := s.GetDataset(ctx, "ds_commit")
		if got.Status != "running" || len(rows) != 0 || d.CurrentRunID != nil {
			t.Fatalf("partial commit visible: status=%s incidents=%d current=%v", got.Status, len(rows), d.CurrentRunID)
		}
		if err := s.CommitRun(ctx, app.CommitSet{Run: run, Incidents: []domain.Incident{inc}, SetCurrent: true}); err != nil {
			t.Fatal(err)
		}
		rows, _ = s.ListIncidents(ctx, "run-1")
		if len(rows) != 1 || rows[0].State.Status != "open" {
			t.Fatalf("after commit: %+v", rows)
		}
	})

	t.Run("AuditChainVerifies", func(t *testing.T) {
		s := newStore(t)
		var wg sync.WaitGroup
		errs := make(chan error, 20)
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 5; i++ {
					subj := fmt.Sprintf("INC-%08d", g)
					_, err := s.AppendAudit(ctx, app.AuditEntry{TS: time.Now(), Actor: "u", Action: "incident.updated", Subject: &subj,
						Payload: json.RawMessage(fmt.Sprintf(`{"z":%d,"a":{"y":1,"b":[1,2]}}`, i))})
					if err != nil {
						errs <- err
					}
				}
			}(g)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		prev, n := app.GenesisHash, int64(0)
		err := s.WalkAudit(ctx, func(e app.AuditEntry) error {
			n++
			subj := ""
			if e.Subject != nil {
				subj = *e.Subject
			}
			if e.Seq != n || e.PrevHash != prev || app.AuditHash(prev, e.TS, e.Actor, e.Action, subj, e.Payload) != e.Hash {
				return fmt.Errorf("chain breaks at seq %d", e.Seq)
			}
			prev = e.Hash
			return nil
		})
		if err != nil || n != 20 {
			t.Fatalf("walk: %d entries, %v", n, err)
		}
		if st, ok := s.(interface {
			TamperForTest(ctx context.Context) error
		}); ok {
			if err := st.TamperForTest(ctx); err == nil {
				t.Fatal("audit_log accepted an UPDATE; it must be append-only")
			}
		}
	})

	t.Run("RetentionDropsOnlyExpired", func(t *testing.T) {
		s := newStore(t)
		dataset(t, s, "ds_ret")
		old := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
		cur := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
		if _, _, err := s.InsertAlerts(ctx, []domain.Alert{alert("ds_ret", "OLD", old, "a"), alert("ds_ret", "NEW", cur, "a")}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.InsertAuthEvents(ctx, []domain.AuthEvent{
			{DatasetID: "ds_ret", EventID: "E1", TS: old, Username: "a", SrcIP: "1.1.1.1", Result: "success", App: "vpn"},
			{DatasetID: "ds_ret", EventID: "E2", TS: cur, Username: "a", SrcIP: "1.1.1.1", Result: "success", App: "vpn"},
		}); err != nil {
			t.Fatal(err)
		}
		units, _, err := s.RetentionInventory(ctx)
		if err != nil || len(units) != 6 {
			t.Fatalf("inventory before: %d units %v", len(units), err)
		}
		if _, err := s.DropExpired(ctx, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		got, _ := s.LoadAlerts(ctx, "ds_ret")
		if len(got) != 1 || got[0].ID != "NEW" {
			t.Fatalf("after drop: %+v", got)
		}
		edges, _ := s.EntityEdges(ctx, "ds_ret", 365*24*time.Hour)
		if len(edges) != 0 {
			t.Fatalf("entity rows of dropped alerts survived: %+v", edges)
		}
		units, _, _ = s.RetentionInventory(ctx)
		for _, u := range units {
			if u.From.Before(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) {
				t.Fatalf("expired unit still listed: %+v", u)
			}
		}
	})

	t.Run("ConcurrentFeedbackSerialises", func(t *testing.T) {
		s := newStore(t)
		if err := s.SeedRuleStats(ctx, []domain.RuleStat{{RuleID: "R1", RuleName: "r", Source: "edr", Alpha: 1, Beta: 1}}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.ApplyVerdict(ctx, []string{"R1", "R1"}, true); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		m, _ := s.RuleStatMap(ctx)
		if m["R1"].Alpha != 11 || m["R1"].Confirmed != 10 {
			t.Fatalf("lost updates: %+v", m["R1"])
		}
	})

	t.Run("IncidentStateIsOptimistic", func(t *testing.T) {
		s := newStore(t)
		dataset(t, s, "ds_state")
		run := app.Run{RunID: "run-s", DatasetID: "ds_state", Status: "running", RequestedBy: "u", CreatedAt: t0}
		_ = s.CreateRun(ctx, run)
		inc := domain.Incident{ID: "INC-0000000a", Rank: 1, Label: "single", Priority: "P3", Cohesion: "solid", FirstSeen: t0, LastSeen: t0}
		if err := s.CommitRun(ctx, app.CommitSet{Run: run, Incidents: []domain.Incident{inc}}); err != nil {
			t.Fatal(err)
		}
		st, err := s.UpdateIncidentState(ctx, app.IncidentState{IncidentID: inc.ID, Status: "investigating"}, 1, t0)
		if err != nil || st.Version != 2 {
			t.Fatalf("update: %+v %v", st, err)
		}
		_, err = s.UpdateIncidentState(ctx, app.IncidentState{IncidentID: inc.ID, Status: "closed"}, 1, t0)
		if de, ok := domain.AsError(err); !ok || de.Code != "PRECONDITION_FAILED" {
			t.Fatalf("stale version should fail with PRECONDITION_FAILED, got %v", err)
		}
	})

	t.Run("DuplicatesAreConflicts", func(t *testing.T) {
		s := newStore(t)
		sup := domain.Suppression{RuleID: "R", EntityKey: "ip:1.1.1.1", CreatedBy: "u", CreatedAt: t0}
		if _, err := s.CreateSuppression(ctx, sup); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateSuppression(ctx, sup); !isCode(err, "ALREADY_EXISTS") {
			t.Fatalf("duplicate suppression: %v", err)
		}
		dataset(t, s, "ds_dup")
		err := s.CreateDataset(ctx, app.Dataset{DatasetID: "ds_dup", Kind: "ingested", WindowStart: t0, WindowEnd: t0, CreatedAt: t0})
		if !isCode(err, "ALREADY_EXISTS") {
			t.Fatalf("duplicate dataset: %v", err)
		}
	})
}

func isCode(err error, code string) bool {
	de, ok := domain.AsError(err)
	return ok && de.Code == code
}

// components returns a canonical string of the partition produced by link.
func components(alerts []domain.Alert, edges func(link func(a, b string))) string {
	parent := map[string]string{}
	for _, a := range alerts {
		parent[a.ID] = a.ID
	}
	var find func(string) string
	find = func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	edges(func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			if ra < rb {
				parent[rb] = ra
			} else {
				parent[ra] = rb
			}
		}
	})
	groups := map[string][]string{}
	for id := range parent {
		r := find(id)
		groups[r] = append(groups[r], id)
	}
	var out []string
	for _, g := range groups {
		sort.Strings(g)
		out = append(out, fmt.Sprint(g))
	}
	sort.Strings(out)
	return fmt.Sprint(out)
}

package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

const EngineVersion = "2.0.0"

// Deps are the ports and settings the services need. cmd/api/main.go is the
// only place that fills them in.
type Deps struct {
	Store      Store
	Pub        Publisher
	LLM        LLM
	Clock      Clock
	Log        *slog.Logger
	Attack     *attack.Catalog
	Engine     correlate.Config
	DataDir    string
	Version    string
	Commit     string
	JWTSecret  []byte
	DemoMode   bool
	LLMEnabled bool
}

// App holds every use-case service. Methods are grouped by file: ingest,
// runs, incidents, narratives, feedback, compliance, adversary, evaluation.
type App struct {
	Deps

	runQueue      chan runJob
	campaignQueue chan string
	narrateQueue  chan narrateJob
	cancelMu      sync.Mutex
	cancels       map[string]context.CancelFunc
	breaker       breaker
	wg            sync.WaitGroup
	stopOnce      sync.Once
	stop          chan struct{}
}

func New(d Deps) *App {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &App{
		Deps:          d,
		runQueue:      make(chan runJob, 4),
		campaignQueue: make(chan string, 2),
		narrateQueue:  make(chan narrateJob, 512),
		cancels:       map[string]context.CancelFunc{},
		stop:          make(chan struct{}),
	}
}

// Start launches the background workers: one run executor, one adversary
// executor, two narrative workers and the maintenance ticker.
func (a *App) Start(ctx context.Context) {
	a.wg.Add(5)
	go a.runWorker(ctx)
	go a.campaignWorker(ctx)
	go a.narrateWorker(ctx)
	go a.narrateWorker(ctx)
	go a.maintenance(ctx)
}

// Stop drains workers; an in-flight run is marked failed("shutdown").
func (a *App) Stop(ctx context.Context) {
	a.stopOnce.Do(func() {
		close(a.stop)
		a.cancelMu.Lock()
		for _, c := range a.cancels {
			c()
		}
		a.cancelMu.Unlock()
	})
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (a *App) now() time.Time { return a.Clock.Now().UTC() }

// Setup seeds reference data: users, the CMDB (when empty) and rule priors.
func (a *App) Setup(ctx context.Context, leadPassword, analystPassword string) error {
	if err := a.Store.SeedRuleStats(ctx, simulate.AllRuleStats()); err != nil {
		return err
	}
	assets, err := a.Store.ListAssets(ctx, 0, "")
	if err != nil {
		return err
	}
	if len(assets) == 0 {
		for _, as := range simulate.CMDB() {
			as.UpdatedAt = a.now()
			if _, err := a.Store.UpsertAsset(ctx, as); err != nil {
				return err
			}
		}
	}
	users := []struct{ id, name, display, role, pw string }{
		{"u_meow", "meow", "Meow", "lead", leadPassword},
		{"u_analyst", "analyst", "Asha (Tier 1)", "analyst", analystPassword},
	}
	for _, u := range users {
		if u.pw == "" {
			continue
		}
		existing, err := a.Store.UserByID(ctx, u.id)
		if err == nil && VerifyPassword(existing.PasswordHash, u.pw) {
			continue
		}
		if err := a.Store.UpsertUser(ctx, User{UserID: u.id, Username: u.name, DisplayName: u.display, Role: u.role, PasswordHash: HashPassword(u.pw)}); err != nil {
			return err
		}
	}
	return nil
}

// audit appends one entry to the hash chain inside the caller's transaction.
func (a *App) audit(ctx context.Context, s Store, actor, action, subject string, payload any) (AuditEntry, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return AuditEntry{}, err
	}
	e := AuditEntry{TS: a.now(), Actor: actor, Action: action, Payload: b}
	if subject != "" {
		e.Subject = &subject
	}
	return s.AppendAudit(ctx, e)
}

// notify publishes a global event for the notification stream.
func (a *App) notify(typ string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["type"] = typ
	fields["at"] = a.now().Format(time.RFC3339)
	a.Pub.Publish(GlobalTopic, typ, fields)
}

const GlobalTopic = "global"

func RunTopic(id string) string      { return "run:" + id }
func CampaignTopic(id string) string { return "campaign:" + id }

// EngineConfig returns the defaults with the dataset's recorded cuts.
func (a *App) engineConfig(cuts []Cut) correlate.Config {
	cfg := a.Engine
	cfg.Cuts = nil
	for _, c := range cuts {
		cfg.Cuts = append(cfg.Cuts, domain.Cut{AlertA: c.AlertA, AlertB: c.AlertB})
	}
	return cfg
}

// Audit appends to the hash chain within s (a store or a transaction). The
// HTTP layer uses it for mutations that do not go through a service.
func (a *App) Audit(ctx context.Context, s Store, actor, action, subject string, payload any) error {
	_, err := a.audit(ctx, s, actor, action, subject, payload)
	return err
}

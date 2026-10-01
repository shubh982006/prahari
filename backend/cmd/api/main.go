// Command api is the composition root: the only file that knows every
// adapter. It loads config, opens the store (SQLite or Postgres by DSN),
// chooses the event bus, wires the services and serves HTTP until signalled.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"prahari/internal/adapters/broker/inproc"
	"prahari/internal/adapters/broker/pgnotify"
	"prahari/internal/adapters/clock"
	"prahari/internal/adapters/llm/azureopenai"
	"prahari/internal/adapters/store/sqlstore"
	"prahari/internal/app"
	"prahari/internal/config"
	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/risk"
	"prahari/internal/httpapi"
)

// Set with -ldflags "-X main.version=… -X main.commit=…".
var (
	version = app.EngineVersion
	commit  = "dev"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "prahari:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", config.Resolve("config.yaml"), "path to config.yaml (optional)")
	flag.Parse()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	log.Info("starting", "version", version, "commit", commit, "config", cfg.Redacted())
	if cfg.GeneratedSecret {
		log.Warn("no PRAHARI_JWT_SECRET set: generated a random one for this process (demo mode); tokens will not survive a restart")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cat, err := attack.LoadFile(cfg.AttackBundle)
	if err != nil {
		return fmt.Errorf("ATT&CK bundle: %w (refusing to correlate without stage data; set PRAHARI_HOME to the backend directory or PRAHARI_ATTACK_BUNDLE to the file)", err)
	}
	log.Info("attack bundle loaded", "version", cat.Version, "techniques", cat.Len(), "hash", cat.Hash)

	store, err := sqlstore.Open(ctx, cfg.DSN)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer store.Close()
	if cfg.AutoMigrate || store.Dialect() == sqlstore.SQLite {
		applied, err := store.Migrate(ctx)
		if err != nil {
			return err
		}
		if len(applied) > 0 {
			log.Info("migrations applied", "migrations", applied)
		}
	}

	var pub app.Publisher
	if store.Dialect() == sqlstore.Postgres {
		pub, err = pgnotify.New(ctx, cfg.DSN, log)
		if err != nil {
			return fmt.Errorf("event bus: %w", err)
		}
	} else {
		pub = inproc.New()
	}

	var llm app.LLM = azureopenai.Disabled{}
	if cfg.LLMEnabled {
		llm = azureopenai.New(azureopenai.Config{Endpoint: cfg.Azure.Endpoint, APIKey: cfg.Azure.APIKey,
			Deployment: cfg.Azure.Deployment, APIVersion: cfg.Azure.APIVersion})
	}

	engine := correlate.Config{
		LinkWindow: cfg.LinkWindow, SupernodeRatio: cfg.SupernodeRatio, SupernodeMinDF: cfg.SupernodeMinDF,
		Weights: risk.DefaultWeights, Capacity: risk.Capacity{P1PerShift: cfg.CapacityP1, P2PerShift: cfg.CapacityP2},
		LaunderingPass: cfg.LaunderingPass, BandMode: cfg.BandMode,
	}
	a := app.New(app.Deps{
		Store: store, Pub: pub, LLM: llm, Clock: clock.System{}, Log: log, Attack: cat, Engine: engine,
		DataDir: cfg.DataDir, Version: version, Commit: commit, JWTSecret: []byte(cfg.JWTSecret),
		DemoMode: cfg.DemoMode, LLMEnabled: cfg.LLMEnabled,
	})

	lead, analyst := cfg.LeadPassword, cfg.AnalystPassword
	if cfg.DemoMode {
		// Only the built-in demo passwords are ever logged; a password supplied
		// through the environment is a secret and stays out of the logs.
		shown := func(user, def string, set *string) string {
			if *set == "" {
				*set = def
				return user + " / " + def + " (built-in demo password)"
			}
			return user + " / (set from the environment)"
		}
		log.Warn("demo mode", "lead", shown("meow", "prahari-lead", &lead), "analyst", shown("analyst", "prahari-analyst", &analyst))
	} else if lead == "" {
		log.Warn("no PRAHARI_LEAD_PASSWORD set; the lead account is not created")
	}
	if err := a.Setup(ctx, lead, analyst); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	a.Start(ctx)

	if cfg.SeedDemo {
		go func() {
			if err := a.SeedDemo(ctx); err != nil {
				log.Warn("demo seed failed", "err", err)
			}
		}()
	}

	ready := func(ctx context.Context) (bool, string) {
		if err := store.Ping(ctx); err != nil {
			return false, "database unreachable"
		}
		if ok, err := store.MigrationsCurrent(ctx); err != nil || !ok {
			return false, "migrations not current"
		}
		if cat.Len() == 0 {
			return false, "ATT&CK bundle empty"
		}
		return true, ""
	}
	api := httpapi.New(a, cfg, log, ready)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: SSE streams are long-lived and send a ping every 15 s.
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr, "dialect", store.Dialect())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	// Streams first: they would otherwise hold Shutdown for its full timeout
	// while every client stares at a connection that will never speak again.
	api.CloseStreams()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.Stop(shutdown)
	_ = srv.Shutdown(shutdown)
	return nil
}

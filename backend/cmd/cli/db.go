package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"prahari/internal/adapters/store/sqlstore"
	"prahari/internal/app"
	"prahari/internal/config"
)

func dsnFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("PRAHARI_DB_DSN")
	if def == "" {
		def = config.SQLiteDSN()
	}
	return fs.String("dsn", def, "database DSN (postgres://… or a SQLite path)")
}

// cmdMigrate applies pending migrations; Compose runs it as a one-shot step
// before the API starts on Postgres.
func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dsn := dsnFlag(fs)
	_ = fs.Parse(args)
	ctx := context.Background()
	s, err := sqlstore.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer s.Close()
	applied, err := s.Migrate(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Printf("%s: schema is current\n", s.Dialect())
		return nil
	}
	for _, m := range applied {
		fmt.Printf("%s: applied %s\n", s.Dialect(), m)
	}
	return nil
}

// cmdVerify recomputes the audit hash chain offline. Exit status 1 when the
// chain is broken, so it can gate a pipeline.
func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dsn := dsnFlag(fs)
	_ = fs.Parse(args)
	ctx := context.Background()
	s, err := sqlstore.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer s.Close()
	a := app.New(app.Deps{Store: s, Clock: systemClock{}})
	v, err := a.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
	if !v.OK {
		os.Exit(1)
	}
	return nil
}

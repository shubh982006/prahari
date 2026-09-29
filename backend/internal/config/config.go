// Package config loads config.yaml, applies PRAHARI_* environment overrides
// and validates the result. Invalid configuration fails at startup, never at
// the first request.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Azure struct {
	Endpoint   string `yaml:"endpoint"`
	APIKey     string `yaml:"api_key"`
	Deployment string `yaml:"deployment"`
	APIVersion string `yaml:"api_version"`
}

type Config struct {
	DSN             string        `yaml:"db_dsn"`
	HTTPAddr        string        `yaml:"http_addr"`
	Replicas        int           `yaml:"replicas"`
	JWTSecret       string        `yaml:"jwt_secret"`
	LinkWindow      time.Duration `yaml:"link_window"`
	SupernodeRatio  float64       `yaml:"supernode_ratio"`
	SupernodeMinDF  int           `yaml:"supernode_min_df"`
	LaunderingPass  bool          `yaml:"laundering_pass"`
	CapacityP1      int           `yaml:"capacity_p1"`
	CapacityP2      int           `yaml:"capacity_p2"`
	BandMode        string        `yaml:"band_mode"`
	AttackBundle    string        `yaml:"attack_bundle"`
	DataDir         string        `yaml:"data_dir"`
	LLMEnabled      bool          `yaml:"llm_enabled"`
	DemoMode        bool          `yaml:"demo_mode"`
	AutoMigrate     bool          `yaml:"auto_migrate"`
	SeedDemo        bool          `yaml:"seed_demo"`
	LeadPassword    string        `yaml:"lead_password"`
	AnalystPassword string        `yaml:"analyst_password"`
	CORSOrigins     []string      `yaml:"cors_origins"`
	LogLevel        string        `yaml:"log_level"`
	Azure           Azure         `yaml:"azure_openai"`

	// GeneratedSecret is true when no JWT secret was configured and a random
	// one was generated for this process (demo mode only).
	GeneratedSecret bool `yaml:"-"`
}

func Defaults() Config {
	return Config{
		DSN:            "file:prahari.db",
		HTTPAddr:       ":8000",
		Replicas:       1,
		LinkWindow:     2 * time.Hour,
		SupernodeRatio: 0.05,
		SupernodeMinDF: 20,
		LaunderingPass: true,
		CapacityP1:     5,
		CapacityP2:     10,
		BandMode:       "calibrated",
		AttackBundle:   "data/attack/enterprise-attack-19.0.min.json",
		DataDir:        "data",
		LLMEnabled:     false,
		DemoMode:       true,
		AutoMigrate:    true,
		SeedDemo:       true,
		LogLevel:       "info",
		CORSOrigins:    []string{"http://localhost:5173", "http://localhost:8080"},
	}
}

// Load reads path (missing is fine), then the environment, then validates.
func Load(path string) (Config, error) {
	c := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err == nil {
			if err := yaml.Unmarshal(b, &c); err != nil {
				return c, fmt.Errorf("config %s: %w", path, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return c, err
		}
	}
	if err := c.env(); err != nil {
		return c, err
	}
	return c, c.validate()
}

func (c *Config) env() error {
	str := func(k string, dst *string) {
		if v, ok := os.LookupEnv(k); ok {
			*dst = v
		}
	}
	var errs []string
	intv := func(k string, dst *int) {
		if v, ok := os.LookupEnv(k); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, k+" must be an integer")
				return
			}
			*dst = n
		}
	}
	boolv := func(k string, dst *bool) {
		if v, ok := os.LookupEnv(k); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, k+" must be true or false")
				return
			}
			*dst = b
		}
	}
	floatv := func(k string, dst *float64) {
		if v, ok := os.LookupEnv(k); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				errs = append(errs, k+" must be a number")
				return
			}
			*dst = f
		}
	}
	durv := func(k string, dst *time.Duration) {
		if v, ok := os.LookupEnv(k); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, k+" must be a duration like 2h")
				return
			}
			*dst = d
		}
	}
	str("PRAHARI_DB_DSN", &c.DSN)
	str("PRAHARI_HTTP_ADDR", &c.HTTPAddr)
	intv("PRAHARI_REPLICAS", &c.Replicas)
	str("PRAHARI_JWT_SECRET", &c.JWTSecret)
	durv("PRAHARI_LINK_WINDOW", &c.LinkWindow)
	floatv("PRAHARI_SUPERNODE_RATIO", &c.SupernodeRatio)
	intv("PRAHARI_SUPERNODE_MIN_DF", &c.SupernodeMinDF)
	boolv("PRAHARI_LAUNDERING_PASS", &c.LaunderingPass)
	intv("PRAHARI_CAPACITY_P1", &c.CapacityP1)
	intv("PRAHARI_CAPACITY_P2", &c.CapacityP2)
	str("PRAHARI_BAND_MODE", &c.BandMode)
	str("PRAHARI_ATTACK_BUNDLE", &c.AttackBundle)
	str("PRAHARI_DATA_DIR", &c.DataDir)
	boolv("PRAHARI_LLM_ENABLED", &c.LLMEnabled)
	boolv("PRAHARI_DEMO_MODE", &c.DemoMode)
	boolv("PRAHARI_AUTO_MIGRATE", &c.AutoMigrate)
	boolv("PRAHARI_SEED_DEMO", &c.SeedDemo)
	str("PRAHARI_LEAD_PASSWORD", &c.LeadPassword)
	str("PRAHARI_ANALYST_PASSWORD", &c.AnalystPassword)
	str("PRAHARI_LOG_LEVEL", &c.LogLevel)
	if v, ok := os.LookupEnv("PRAHARI_CORS_ORIGINS"); ok {
		c.CORSOrigins = nil
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" {
				c.CORSOrigins = append(c.CORSOrigins, o)
			}
		}
	}
	str("AZURE_OPENAI_ENDPOINT", &c.Azure.Endpoint)
	str("AZURE_OPENAI_API_KEY", &c.Azure.APIKey)
	str("AZURE_OPENAI_DEPLOYMENT", &c.Azure.Deployment)
	str("AZURE_OPENAI_API_VERSION", &c.Azure.APIVersion)
	if len(errs) > 0 {
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}

func (c *Config) IsPostgres() bool {
	return strings.HasPrefix(c.DSN, "postgres://") || strings.HasPrefix(c.DSN, "postgresql://")
}

func (c *Config) validate() error {
	var errs []string
	if !c.IsPostgres() && c.Replicas > 1 {
		errs = append(errs, "PRAHARI_REPLICAS > 1 requires Postgres: the SQLite event bus is in-process, so a second instance would silently miss events")
	}
	if c.LinkWindow < time.Minute || c.LinkWindow > 48*time.Hour {
		errs = append(errs, "link_window must be between 1m and 48h")
	}
	if c.SupernodeRatio <= 0 || c.SupernodeRatio > 0.5 {
		errs = append(errs, "supernode_ratio must be in (0, 0.5]")
	}
	if c.CapacityP1 < 1 || c.CapacityP2 < 1 {
		errs = append(errs, "capacity_p1 and capacity_p2 must be at least 1")
	}
	if c.BandMode != "calibrated" && c.BandMode != "fixed" {
		errs = append(errs, "band_mode must be calibrated or fixed")
	}
	if c.JWTSecret == "" {
		if !c.DemoMode {
			errs = append(errs, "PRAHARI_JWT_SECRET is required outside demo mode (32+ random bytes)")
		} else {
			b := make([]byte, 32)
			_, _ = rand.Read(b)
			c.JWTSecret = hex.EncodeToString(b)
			c.GeneratedSecret = true
		}
	} else if len(c.JWTSecret) < 32 {
		errs = append(errs, "PRAHARI_JWT_SECRET must be at least 32 bytes")
	}
	if c.LLMEnabled && (c.Azure.Endpoint == "" || c.Azure.APIKey == "" || c.Azure.Deployment == "") {
		errs = append(errs, "PRAHARI_LLM_ENABLED=true needs AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY and AZURE_OPENAI_DEPLOYMENT")
	}
	if len(errs) > 0 {
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}

// Redacted is the config as it may be logged.
func (c Config) Redacted() map[string]any {
	dsn := c.DSN
	if i := strings.Index(dsn, "@"); i > 0 && c.IsPostgres() {
		if j := strings.Index(dsn, "://"); j > 0 {
			dsn = dsn[:j+3] + "***" + dsn[i:]
		}
	}
	return map[string]any{
		"dsn": dsn, "http_addr": c.HTTPAddr, "replicas": c.Replicas, "link_window": c.LinkWindow.String(),
		"supernode_ratio": c.SupernodeRatio, "laundering_pass": c.LaunderingPass, "band_mode": c.BandMode,
		"llm_enabled": c.LLMEnabled, "demo_mode": c.DemoMode, "attack_bundle": c.AttackBundle,
	}
}

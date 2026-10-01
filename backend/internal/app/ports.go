// Package app holds the use-case services and the ports they depend on. It
// knows no adapter: storage, the event bus, the LLM and the clock are
// interfaces here and implementations elsewhere.
package app

import (
	"context"
	"encoding/json"
	"time"

	"prahari/internal/domain"
)

// Store is the persistence port. Two adapters implement it (Postgres and
// SQLite) and one conformance suite tests both. Dialect exists for /meta
// only; no business logic may branch on it.
type Store interface {
	InTx(ctx context.Context, fn func(tx Store) error) error
	Dialect() string
	Ping(ctx context.Context) error
	Close() error

	// users
	UserByUsername(ctx context.Context, username string) (User, error)
	UserByID(ctx context.Context, id string) (User, error)
	UpsertUser(ctx context.Context, u User) error

	// assets
	ListAssets(ctx context.Context, minCriticality int, dataClass string) ([]domain.Asset, error)
	GetAsset(ctx context.Context, hostname string) (domain.Asset, error)
	UpsertAsset(ctx context.Context, a domain.Asset) (created bool, err error)
	AssetMap(ctx context.Context) (map[string]domain.Asset, error)

	// datasets
	CreateDataset(ctx context.Context, d Dataset) error
	GetDataset(ctx context.Context, id string) (Dataset, error)
	ListDatasets(ctx context.Context, kind string, limit int, after *time.Time, afterID string) ([]Dataset, error)
	AddDatasetCounts(ctx context.Context, id string, authEvents, alerts, detectorAlerts int) error
	ExtendDatasetWindow(ctx context.Context, id string, from, to time.Time) error
	SetCurrentRun(ctx context.Context, datasetID, runID string) error

	// ingest
	InsertAuthEvents(ctx context.Context, events []domain.AuthEvent) (inserted, dup int, err error)
	AuthEventsBetween(ctx context.Context, datasetID string, from, to time.Time) ([]domain.AuthEvent, error)
	InsertAlerts(ctx context.Context, alerts []domain.Alert) (inserted, dup int, err error)

	// alerts
	ListAlerts(ctx context.Context, f AlertFilter) ([]domain.Alert, error)
	AlertStats(ctx context.Context, datasetID string) (AlertStats, error)
	GetAlert(ctx context.Context, datasetID, id string) (domain.Alert, error)
	LoadAlerts(ctx context.Context, datasetID string) ([]domain.Alert, error)
	AlertsByID(ctx context.Context, datasetID string, ids []string) ([]domain.Alert, error)
	// EntityEdges pushes consecutive-pair linking into SQL (design §6.3).
	EntityEdges(ctx context.Context, datasetID string, window time.Duration) ([]domain.Edge, error)

	// runs
	TryLock(ctx context.Context, datasetID, runID string, now time.Time, ttl time.Duration) (ok bool, activeRunID string, err error)
	Unlock(ctx context.Context, datasetID, runID string) error
	ReapStaleLocks(ctx context.Context, now time.Time) ([]RunLock, error)
	CreateRun(ctx context.Context, r Run) error
	GetRun(ctx context.Context, runID string) (Run, error)
	ListRuns(ctx context.Context, datasetID string, limit int, after *time.Time, afterID string) ([]Run, error)
	StartRun(ctx context.Context, runID string, at time.Time) error
	FailRun(ctx context.Context, runID, status, reason string, at time.Time) error
	CommitRun(ctx context.Context, set CommitSet) error

	// incidents
	ListIncidents(ctx context.Context, runID string) ([]IncidentRow, error)
	GetIncident(ctx context.Context, runID, incidentID string) (IncidentRow, error)
	IncidentState(ctx context.Context, incidentID string) (IncidentState, error)
	UpdateIncidentState(ctx context.Context, s IncidentState, expectVersion int, at time.Time) (IncidentState, error)
	RulesInRun(ctx context.Context, runID string) (map[string]int, error)

	// narratives
	GetNarrative(ctx context.Context, factsHash string) (StoredNarrative, error)
	PutNarrative(ctx context.Context, n StoredNarrative) error

	// learning
	ListRuleStats(ctx context.Context) ([]domain.RuleStat, error)
	RuleStatMap(ctx context.Context) (map[string]domain.RuleStat, error)
	SeedRuleStats(ctx context.Context, stats []domain.RuleStat) error
	ApplyVerdict(ctx context.Context, ruleIDs []string, confirmed bool) ([]RuleUpdate, error)
	ListSuppressions(ctx context.Context) ([]domain.Suppression, error)
	CreateSuppression(ctx context.Context, s domain.Suppression) (domain.Suppression, error)
	DeleteSuppression(ctx context.Context, id int64) error
	CreateFeedback(ctx context.Context, f Feedback) (Feedback, error)
	ListFeedback(ctx context.Context, incidentID string) ([]Feedback, error)
	AddCut(ctx context.Context, c Cut) error
	ListCuts(ctx context.Context, datasetID string) ([]Cut, error)

	// compliance
	CaseByIncident(ctx context.Context, incidentID string) (Case, error)
	NextCaseID(ctx context.Context) (string, error)
	ListCases(ctx context.Context, datasetID string) ([]Case, error)
	GetCase(ctx context.Context, caseID string) (Case, error)
	GetTrack(ctx context.Context, caseID, track string) (Track, error)
	RecordSubmission(ctx context.Context, caseID, track, by, reference, note string, at time.Time) error

	// audit
	AppendAudit(ctx context.Context, e AuditEntry) (AuditEntry, error)
	ListAudit(ctx context.Context, subject, action string, limit int, beforeSeq int64) ([]AuditEntry, error)
	WalkAudit(ctx context.Context, fn func(AuditEntry) error) error

	// adversary
	CreateCampaign(ctx context.Context, c Campaign) error
	UpdateCampaign(ctx context.Context, id, status string, finished *time.Time, durationMS *int64, errMsg *string) error
	GetCampaign(ctx context.Context, id string) (Campaign, error)
	ListCampaigns(ctx context.Context, baseDataset string, limit int, after *time.Time, afterID string) ([]Campaign, error)
	PutEvasionResult(ctx context.Context, r EvasionResult) error
	EvasionResults(ctx context.Context, campaignID string) ([]EvasionResult, error)

	// evaluations
	PutEvaluation(ctx context.Context, e Evaluation) error
	LatestEvaluation(ctx context.Context, datasetID string) (Evaluation, error)
	// PutTruth replaces a dataset's ground truth; GetTruth answers NOT_FOUND when there is none.
	PutTruth(ctx context.Context, datasetID string, body []byte, at time.Time) error
	GetTruth(ctx context.Context, datasetID string) ([]byte, error)

	// idempotency
	GetIdempotent(ctx context.Context, userID, route, key string, since time.Time) (IdempotentResponse, bool, error)
	PutIdempotent(ctx context.Context, userID, route, key string, r IdempotentResponse, at time.Time) error

	// retention
	DropExpired(ctx context.Context, before time.Time) (int64, error)
	RetentionInventory(ctx context.Context) ([]RetentionUnit, string, error)
}

// Event is one server-sent event.
type Event struct {
	ID    string
	Topic string
	Type  string
	Data  json.RawMessage
}

// Publisher is the event bus port: in-process for SQLite, LISTEN/NOTIFY for
// multi-instance Postgres.
type Publisher interface {
	Publish(topic, typ string, data any)
	// Subscribe replays events after lastID, then streams. cancel releases
	// the subscription. closed reports that the topic has finished.
	Subscribe(topic, lastID string) (replay []Event, ch <-chan Event, cancel func())
	Close(topic string)
	Subscribers() int
}

// LLM is the narration model port.
type LLM interface {
	Complete(ctx context.Context, system, user string, schema map[string]any) (content, model string, err error)
	Enabled() bool
}

// Clock is injected so services and tests agree on time.
type Clock interface{ Now() time.Time }

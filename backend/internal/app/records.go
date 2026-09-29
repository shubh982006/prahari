package app

import (
	"encoding/json"
	"time"

	"prahari/internal/domain"
)

// Records are what the Store persists. They are plain data; services own the
// behaviour.

type User struct {
	UserID       string `json:"user_id"`
	Username     string `json:"-"`
	DisplayName  string `json:"display_name"`
	Role         string `json:"role"`
	PasswordHash string `json:"-"`
}

type Dataset struct {
	DatasetID        string    `json:"dataset_id"`
	Kind             string    `json:"kind"`
	Seed             *int64    `json:"seed"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	Scenarios        []string  `json:"scenarios"`
	AuthEvents       int       `json:"-"`
	Alerts           int       `json:"-"`
	AlertsByDetector int       `json:"-"`
	HasTruth         bool      `json:"has_truth"`
	ParentID         *string   `json:"parent_id"`
	CurrentRunID     *string   `json:"current_run_id"`
	CreatedAt        time.Time `json:"created_at"`
}

type AlertFilter struct {
	DatasetID string
	From, To  *time.Time
	Sources   []string
	Severity  []string
	RuleID    string
	Entity    string
	Q         string
	Desc      bool
	Limit     int
	After     *AlertCursor
}

type AlertCursor struct {
	TS time.Time `json:"t"`
	ID string    `json:"i"`
}

type AlertStats struct {
	Total      int            `json:"total"`
	BySource   map[string]int `json:"by_source"`
	BySeverity map[string]int `json:"by_severity"`
	ByHour     []HourCount    `json:"by_hour"`
}

type HourCount struct {
	Hour  time.Time `json:"hour"`
	Count int       `json:"count"`
}

type Run struct {
	RunID         string          `json:"run_id"`
	DatasetID     string          `json:"dataset_id"`
	Status        string          `json:"status"`
	RequestedBy   string          `json:"requested_by"`
	Params        json.RawMessage `json:"params"`
	Summary       json.RawMessage `json:"summary"`
	Error         *string         `json:"error"`
	InputHash     string          `json:"-"`
	ConfigHash    string          `json:"-"`
	OutputHash    string          `json:"-"`
	EngineVersion string          `json:"-"`
	AttackVersion string          `json:"-"`
	Dialect       string          `json:"-"`
	Bands         *domain.Bands   `json:"-"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
	ComputedAt    *time.Time      `json:"-"`
}

// IncidentRow is an incident as committed for one run, plus its mutable
// analyst state (keyed on the stable ID, so it survives re-runs).
type IncidentRow struct {
	RunID    string
	Incident domain.Incident
	State    IncidentState
	CaseID   *string
}

type IncidentState struct {
	IncidentID string    `json:"incident_id"`
	Status     string    `json:"status"`
	Assignee   *string   `json:"assignee"`
	Version    int       `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CommitSet is everything one run writes, in one transaction: either the run
// is fully visible or it never happened.
type CommitSet struct {
	Run        Run
	Incidents  []domain.Incident
	FactsHash  map[string]string
	Cases      []Case
	SetCurrent bool
}

type StoredNarrative struct {
	FactsHash   string          `json:"facts_hash"`
	IncidentID  string          `json:"incident_id"`
	Source      string          `json:"source"`
	Model       *string         `json:"model"`
	Attempts    int             `json:"attempts"`
	Body        json.RawMessage `json:"body"`
	Validation  json.RawMessage `json:"validation"`
	GeneratedAt time.Time       `json:"generated_at"`
}

type RuleUpdate struct {
	RuleID          string  `json:"rule_id"`
	Alpha           float64 `json:"alpha"`
	Beta            float64 `json:"beta"`
	PrecisionBefore float64 `json:"precision_before"`
	PrecisionAfter  float64 `json:"precision_after"`
}

type Feedback struct {
	FeedbackID int64     `json:"feedback_id"`
	IncidentID string    `json:"incident_id"`
	RunID      string    `json:"run_id"`
	Verdict    string    `json:"verdict"`
	Note       *string   `json:"note"`
	UserID     string    `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type Cut struct {
	DatasetID  string    `json:"dataset_id"`
	AlertA     string    `json:"alert_a"`
	AlertB     string    `json:"alert_b"`
	IncidentID string    `json:"incident_id"`
	Note       string    `json:"note"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

type Case struct {
	CaseID       string               `json:"case_id"`
	IncidentID   string               `json:"incident_id"`
	DatasetID    string               `json:"dataset_id"`
	RunID        string               `json:"run_id"`
	Priority     string               `json:"priority"`
	Headline     string               `json:"headline"`
	DetectedAt   time.Time            `json:"detected_at"`
	Trigger      domain.BreachTrigger `json:"trigger"`
	EvidenceHash string               `json:"evidence_hash"`
	Tracks       []Track              `json:"tracks"`
}

type Track struct {
	CaseID      string          `json:"-"`
	Track       string          `json:"track"`
	Deadline    time.Time       `json:"deadline"`
	Status      string          `json:"status"`
	Draft       json.RawMessage `json:"-"`
	GeneratedAt *time.Time      `json:"-"`
	SubmittedAt *time.Time      `json:"submitted_at"`
	SubmittedBy *string         `json:"submitted_by"`
	Reference   *string         `json:"reference"`
	Note        *string         `json:"-"`
}

type AuditEntry struct {
	Seq      int64           `json:"seq"`
	TS       time.Time       `json:"ts"`
	Actor    string          `json:"actor"`
	Action   string          `json:"action"`
	Subject  *string         `json:"subject"`
	Payload  json.RawMessage `json:"payload"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

type Campaign struct {
	CampaignID  string     `json:"campaign_id"`
	BaseDataset string     `json:"base_dataset"`
	Strategy    string     `json:"strategy"`
	Budgets     []float64  `json:"budgets"`
	Mitigated   bool       `json:"mitigated"`
	Seed        int64      `json:"seed"`
	Status      string     `json:"status"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	FinishedAt  *time.Time `json:"-"`
	DurationMS  *int64     `json:"-"`
	Error       *string    `json:"-"`
}

type EvasionResult struct {
	CampaignID         string  `json:"-"`
	Budget             float64 `json:"budget"`
	VariantDataset     string  `json:"variant_dataset"`
	RunID              string  `json:"run_id"`
	ScenarioRecall     float64 `json:"scenario_recall"`
	PairwisePrecision  float64 `json:"pairwise_precision"`
	PairwiseRecall     float64 `json:"pairwise_recall"`
	Incidents          int     `json:"incidents"`
	Detected           bool    `json:"detected"`
	TopRank            *int    `json:"top_rank"`
	ScenariosEvaluated int     `json:"scenarios_evaluated"`
}

type Evaluation struct {
	EvaluationID string          `json:"evaluation_id"`
	RunID        string          `json:"run_id"`
	DatasetID    string          `json:"dataset_id"`
	CreatedAt    time.Time       `json:"created_at"`
	Body         json.RawMessage `json:"-"`
}

type IdempotentResponse struct {
	BodyHash string
	Status   int
	Body     []byte
	Headers  map[string]string
}

type RetentionUnit struct {
	Table     string    `json:"table"`
	Name      string    `json:"name"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Rows      int64     `json:"rows"`
	DropAfter time.Time `json:"drop_after"`
}

type RunLock struct {
	DatasetID string
	RunID     string
	ExpiresAt time.Time
}

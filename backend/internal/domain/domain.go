// Package domain holds the plain types shared by every layer. It imports only
// the standard library and contains no behaviour beyond small value methods.
package domain

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Score maps severity onto [0,1] for the S factor.
func (s Severity) Score() float64 {
	switch s {
	case SevCritical:
		return 1.0
	case SevHigh:
		return 0.75
	case SevMedium:
		return 0.5
	case SevLow:
		return 0.25
	}
	return 0
}

func (s Severity) Valid() bool { return s.Score() > 0 }

var Sources = []string{"auth", "edr", "network", "cloud", "email"}

type Entities struct {
	Users     []string `json:"users"`
	Hosts     []string `json:"hosts"`
	IPs       []string `json:"ips"`
	Processes []string `json:"processes"`
	Hashes    []string `json:"hashes"`
}

// Normalized returns a copy whose nil slices are empty, so JSON is stable.
func (e Entities) Normalized() Entities {
	fix := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return Entities{fix(e.Users), fix(e.Hosts), fix(e.IPs), fix(e.Processes), fix(e.Hashes)}
}

type Alert struct {
	DatasetID   string          `json:"dataset_id"`
	ID          string          `json:"id"`
	TS          time.Time       `json:"timestamp"`
	Source      string          `json:"source"`
	RuleID      string          `json:"rule_id"`
	RuleName    string          `json:"rule_name"`
	Severity    Severity        `json:"severity"`
	TechniqueID string          `json:"technique_id,omitempty"`
	Entities    Entities        `json:"entities"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

type AuthEvent struct {
	DatasetID string    `json:"dataset_id,omitempty"`
	EventID   string    `json:"event_id"`
	TS        time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	SrcIP     string    `json:"src_ip"`
	Geo       string    `json:"geo,omitempty"`
	Result    string    `json:"result"`
	App       string    `json:"app"`
	IsAdmin   bool      `json:"is_admin,omitempty"`
}

type Asset struct {
	Hostname    string    `json:"hostname"`
	Role        string    `json:"role"`
	Criticality int       `json:"criticality"`
	DataClasses []string  `json:"data_classes"`
	Owner       string    `json:"owner,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Sensitive reports whether the asset holds data that triggers the +0.2 asset
// uplift and the compliance rule.
func (a Asset) Sensitive() bool {
	for _, c := range a.DataClasses {
		if c == "pii" || c == "financial" {
			return true
		}
	}
	return false
}

// RuleStat is the Beta(α,β) posterior for one detection rule.
type RuleStat struct {
	RuleID         string  `json:"rule_id"`
	RuleName       string  `json:"rule_name"`
	Source         string  `json:"source"`
	TechniqueID    string  `json:"technique_id,omitempty"`
	Alpha          float64 `json:"alpha"`
	Beta           float64 `json:"beta"`
	Confirmed      int     `json:"confirmed"`
	FalsePositives int     `json:"false_positives"`
}

func (r RuleStat) Precision() float64 {
	if r.Alpha+r.Beta == 0 {
		return 0.5
	}
	return r.Alpha / (r.Alpha + r.Beta)
}

// Suppression excludes one rule for one entity.
type Suppression struct {
	ID        int64      `json:"suppression_id"`
	RuleID    string     `json:"rule_id"`
	EntityKey string     `json:"entity_key"`
	Reason    string     `json:"reason,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Cut is an analyst-recorded split: the link between two alerts must not be
// used, so the incident it held together becomes two.
type Cut struct {
	AlertA string `json:"alert_a"`
	AlertB string `json:"alert_b"`
}

// Edge links two alerts through one shared entity.
type Edge struct {
	A, B      string // alert IDs, A earlier than B
	EntityKey string
	Laundered bool
}

// ---------- incidents ----------

type Breakdown struct {
	C             float64          `json:"C"`
	S             float64          `json:"S"`
	A             float64          `json:"A"`
	Q             float64          `json:"Q"`
	Weights       Weights          `json:"weights"`
	Risk          float64          `json:"risk"`
	ForwardStages int              `json:"forward_stages"`
	Overrides     []string         `json:"overrides"`
	TopAssets     []BreakdownAsset `json:"top_assets"`
	Rules         []BreakdownRule  `json:"rules"`
}

type BreakdownAsset struct {
	Hostname    string   `json:"hostname"`
	Criticality int      `json:"criticality"`
	DataClasses []string `json:"data_classes"`
	Known       bool     `json:"-"`
}

type BreakdownRule struct {
	RuleID    string  `json:"rule_id"`
	Precision float64 `json:"precision"`
	Alerts    int     `json:"alerts"`
}

type Weights struct {
	C float64 `json:"C"`
	S float64 `json:"S"`
	A float64 `json:"A"`
	Q float64 `json:"Q"`
}

type Bands struct {
	P1 float64 `json:"P1"`
	P2 float64 `json:"P2"`
	P3 float64 `json:"P3"`
}

func (b Bands) Priority(risk float64) string {
	switch {
	case risk >= b.P1:
		return "P1"
	case risk >= b.P2:
		return "P2"
	case risk >= b.P3:
		return "P3"
	}
	return "P4"
}

type IncidentEntity struct {
	Key    string  `json:"key"`
	Weight float64 `json:"weight"`
	Alerts int     `json:"alerts"`
}

type IncidentTechnique struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Stage       int    `json:"stage"`
	Alerts      int    `json:"alerts"`
}

type BridgeEdge struct {
	AlertA    string  `json:"alert_a"`
	AlertB    string  `json:"alert_b"`
	EntityKey string  `json:"entity_key"`
	Weight    float64 `json:"weight"`
	LeftSize  int     `json:"left_size"`
	RightSize int     `json:"right_size"`
}

type SplitHalf struct {
	AlertIDs    []string `json:"alert_ids"`
	Alerts      int      `json:"alerts"`
	MaxStage    int      `json:"max_stage"`
	Headline    string   `json:"headline"`
	EstRisk     float64  `json:"est_risk"`
	EstPriority string   `json:"est_priority"`
}

type SplitPreview struct {
	Left  SplitHalf `json:"left"`
	Right SplitHalf `json:"right"`
}

type GraphNode struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Label       string   `json:"label"`
	External    bool     `json:"external"`
	Criticality *int     `json:"criticality"`
	DataClasses []string `json:"data_classes"`
	Stoplisted  bool     `json:"stoplisted,omitempty"`
}

type GraphEdge struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	AlertID     string    `json:"alert_id"`
	TS          time.Time `json:"ts"`
	Stage       int       `json:"stage"`
	TechniqueID *string   `json:"technique_id"`
	OnChain     bool      `json:"on_chain"`
	Order       int       `json:"order"`
	IsBridge    bool      `json:"is_bridge"`
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type TimelineLane struct {
	Stage   int      `json:"stage"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

type TimelinePoint struct {
	AlertID  string    `json:"alert_id"`
	TS       time.Time `json:"ts"`
	Stage    int       `json:"stage"`
	Severity Severity  `json:"severity"`
	RuleName string    `json:"rule_name"`
	OnChain  bool      `json:"on_chain"`
}

type Timeline struct {
	Lanes  []TimelineLane  `json:"lanes"`
	Points []TimelinePoint `json:"points"`
	Chain  []string        `json:"chain"`
}

// Incident is one correlated group as produced by the engine for one run.
// It is immutable once committed; analyst state lives elsewhere.
type Incident struct {
	ID                 string              `json:"incident_id"`
	Rank               int                 `json:"rank"`
	Headline           string              `json:"headline"`
	Label              string              `json:"label"`
	Priority           string              `json:"priority"`
	Risk               float64             `json:"risk"`
	Confidence         float64             `json:"confidence"`
	Cohesion           string              `json:"cohesion"`
	CohesionReason     string              `json:"cohesion_reason"`
	AlertIDs           []string            `json:"alert_ids"` // time order
	ChainIDs           []string            `json:"chain_ids"` // forward path, in order
	Stages             []int               `json:"stages"`
	MaxStage           int                 `json:"max_stage"`
	ForwardStages      int                 `json:"forward_stages"`
	FirstSeen          time.Time           `json:"first_seen"`
	LastSeen           time.Time           `json:"last_seen"`
	Assets             []string            `json:"assets"`
	LaunderingInferred bool                `json:"laundering_inferred"`
	Breakdown          Breakdown           `json:"breakdown"`
	Entities           []IncidentEntity    `json:"entities"`
	Techniques         []IncidentTechnique `json:"techniques"`
	Sources            map[string]int      `json:"sources"`
	BridgeEdges        []BridgeEdge        `json:"bridge_edges"`
	SplitPreview       *SplitPreview       `json:"split_preview"`
	Graph              Graph               `json:"graph"`
	Timeline           Timeline            `json:"timeline"`
	Breach             *BreachTrigger      `json:"breach"`
	FactsHash          string              `json:"facts_hash"`
}

// BreachTrigger is set when an incident satisfies the compliance rule.
type BreachTrigger struct {
	Priority    string   `json:"priority"`
	MaxStage    int      `json:"max_stage"`
	Assets      []string `json:"assets"`
	DataClasses []string `json:"data_classes"`
}

// Truth is the hidden ground truth for a simulated or adversarial dataset.
// The engine never reads it.
type Truth struct {
	DatasetID string          `json:"dataset_id"`
	Seed      int64           `json:"seed"`
	Scenarios []TruthScenario `json:"scenarios"`
	// Groups maps every alert ID to a truth group: a scenario letter
	// ("A".."F") or a noise group ("noise:<n>").
	Groups map[string]string `json:"groups"`
}

type TruthScenario struct {
	Scenario         string     `json:"scenario"`
	Name             string     `json:"name"`
	ExpectedPriority string     `json:"expected_priority"`
	AlertIDs         []string   `json:"alert_ids"`
	Steps            [][]string `json:"steps"` // alert IDs per attack step, in order
	DeliberateMiss   string     `json:"deliberate_miss,omitempty"`
}

func IsScenarioGroup(g string) bool { return len(g) == 1 && g[0] >= 'A' && g[0] <= 'Z' }

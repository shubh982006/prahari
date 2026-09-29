package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"prahari/internal/core/correlate"
	"prahari/internal/core/evade"
	"prahari/internal/domain"
)

type CampaignInput struct {
	BaseDataset string
	Strategy    string
	Budgets     []float64
	Mitigated   bool
	Seed        int64
}

type CampaignView struct {
	Campaign
	EventsURL string `json:"events_url"`
}

type CampaignDetailView struct {
	CampaignView
	Results    []EvasionResult `json:"results"`
	DurationMS int64           `json:"duration_ms"`
	Error      *string         `json:"error,omitempty"`
}

func campaignView(c Campaign) CampaignView {
	return CampaignView{Campaign: c, EventsURL: "/api/v1/adversary/campaigns/" + c.CampaignID + "/events"}
}

func newCampaignID() string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "camp_" + string(b)
}

// CreateCampaign queues an evasion campaign. It needs a base dataset with
// planted truth, because the whole output is recall against that truth.
func (a *App) CreateCampaign(ctx context.Context, in CampaignInput, actor string) (CampaignView, error) {
	var fe []domain.FieldError
	if !evade.Valid(in.Strategy) {
		fe = append(fe, domain.FieldError{Field: "body.strategy", Message: "must be one of: " + strings.Join(evade.Strategies, ", ")})
	}
	if len(in.Budgets) == 0 {
		in.Budgets = []float64{0, 0.25, 0.5, 0.75, 1}
	}
	seen := map[float64]bool{}
	var budgets []float64
	for _, b := range in.Budgets {
		if b < 0 || b > 1 || math.IsNaN(b) {
			fe = append(fe, domain.FieldError{Field: "body.budgets", Message: "each budget must be between 0 and 1"})
			break
		}
		b = math.Round(b*1000) / 1000
		if !seen[b] {
			seen[b] = true
			budgets = append(budgets, b)
		}
	}
	if len(budgets) < 2 || len(budgets) > 11 {
		fe = append(fe, domain.FieldError{Field: "body.budgets", Message: "between 2 and 11 distinct budgets"})
	}
	if len(fe) > 0 {
		return CampaignView{}, domain.Validation(fe...)
	}
	sort.Float64s(budgets)
	d, err := a.Store.GetDataset(ctx, in.BaseDataset)
	if err != nil {
		return CampaignView{}, err
	}
	if d.Kind == "adversarial" || !d.HasTruth {
		return CampaignView{}, domain.Unprocessable("NO_GROUND_TRUTH", "campaigns need a simulated base dataset with planted truth")
	}
	if _, err := a.readTruth(d.DatasetID); err != nil {
		return CampaignView{}, err
	}
	c := Campaign{CampaignID: newCampaignID(), BaseDataset: d.DatasetID, Strategy: in.Strategy, Budgets: budgets,
		Mitigated: in.Mitigated, Seed: in.Seed, Status: "queued", CreatedBy: actor, CreatedAt: a.now()}
	err = a.Store.InTx(ctx, func(tx Store) error {
		if err := tx.CreateCampaign(ctx, c); err != nil {
			return err
		}
		_, err := a.audit(ctx, tx, actor, "campaign.created", c.CampaignID, map[string]any{
			"base_dataset": c.BaseDataset, "strategy": c.Strategy, "budgets": c.Budgets, "mitigated": c.Mitigated, "seed": c.Seed})
		return err
	})
	if err != nil {
		return CampaignView{}, err
	}
	select {
	case a.campaignQueue <- c.CampaignID:
	default:
		msg := "campaign queue full"
		_ = a.Store.UpdateCampaign(ctx, c.CampaignID, "failed", nil, nil, &msg)
		return CampaignView{}, domain.Conflict("INVALID_STATE", "two campaigns are already queued; try again when one finishes")
	}
	return campaignView(c), nil
}

func (a *App) campaignWorker(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		case id := <-a.campaignQueue:
			if err := a.runCampaign(ctx, id); err != nil {
				a.Log.Warn("campaign failed", "campaign_id", id, "err", err)
			}
		}
	}
}

func (a *App) runCampaign(ctx context.Context, id string) (err error) {
	start := time.Now()
	topic := CampaignTopic(id)
	c, err := a.Store.GetCampaign(ctx, id)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			msg := err.Error()
			fin := a.now()
			_ = a.Store.UpdateCampaign(context.WithoutCancel(ctx), id, "failed", &fin, nil, &msg)
			a.Pub.Publish(topic, "error", map[string]any{"campaign_id": id, "code": "CAMPAIGN_FAILED", "message": msg})
			a.Pub.Close(topic)
		}
	}()
	if err := a.Store.UpdateCampaign(ctx, id, "running", nil, nil, nil); err != nil {
		return err
	}
	base, err := a.Store.LoadAlerts(ctx, c.BaseDataset)
	if err != nil {
		return err
	}
	truth, err := a.readTruth(c.BaseDataset)
	if err != nil {
		return err
	}
	assets, err := a.Store.AssetMap(ctx)
	if err != nil {
		return err
	}
	stats, err := a.Store.RuleStatMap(ctx)
	if err != nil {
		return err
	}
	cfg := a.engineConfig(nil)
	cfg.LaunderingPass = c.Mitigated

	// Recall is measured over the scenarios the engine detects before any
	// mutation, computed with this campaign's own configuration.
	baseOut, err := correlate.Run(correlate.Input{DatasetID: c.BaseDataset, Alerts: base, Assets: assets, RuleStats: stats,
		Attack: a.Attack, Config: cfg, RunStarted: a.now()}, correlate.Hooks{})
	if err != nil {
		return err
	}
	consider := evade.Baseline(baseOut.Incidents, truth, alertOrder(base))

	params := evade.Params{LinkWindow: cfg.LinkWindow, SupernodeRatio: cfg.SupernodeRatio, SupernodeMinDF: cfg.SupernodeMinDF, FloodTarget: floodTarget(assets)}
	short := strings.ToLower(strings.TrimPrefix(id, "camp_"))
	for _, b := range c.Budgets {
		a.Pub.Publish(topic, "budget.started", map[string]any{"campaign_id": id, "budget": b})
		vid := fmt.Sprintf("ds_adv_%s_b%03d", short, int(math.Round(b*100)))
		v, err := evade.Generate(base, truth, c.Strategy, b, c.Seed, params, vid)
		if err != nil {
			return err
		}
		lo, hi := v.Alerts[0].TS, v.Alerts[len(v.Alerts)-1].TS
		parent := c.BaseDataset
		seed := c.Seed
		if err := a.Store.CreateDataset(ctx, Dataset{DatasetID: vid, Kind: "adversarial", Seed: &seed, WindowStart: lo, WindowEnd: hi.Add(time.Second),
			Scenarios: []string{}, HasTruth: true, ParentID: &parent, CreatedAt: a.now()}); err != nil {
			return err
		}
		if err := a.writeTruth(v.Truth); err != nil {
			return err
		}
		ins, _, err := a.Store.InsertAlerts(ctx, v.Alerts)
		if err != nil {
			return err
		}
		if err := a.Store.AddDatasetCounts(ctx, vid, 0, ins, 0); err != nil {
			return err
		}
		run, err := a.createRun(ctx, vid, "system", cfg, RunParams{})
		if err != nil {
			return err
		}
		res, err := a.execute(ctx, runJob{runID: run.RunID, datasetID: vid, actor: "system", cfg: cfg, internal: true})
		if err != nil {
			return err
		}
		p := evade.Score(b, res.incidents, v.Truth, consider, alertOrder(v.Alerts))
		r := EvasionResult{CampaignID: id, Budget: b, VariantDataset: vid, RunID: run.RunID, ScenarioRecall: p.ScenarioRecall,
			PairwisePrecision: p.PairwisePrecision, PairwiseRecall: p.PairwiseRecall, Incidents: p.Incidents, Detected: p.Detected,
			TopRank: p.TopRank, ScenariosEvaluated: p.ScenariosEvaluated}
		if err := a.Store.PutEvasionResult(ctx, r); err != nil {
			return err
		}
		a.Pub.Publish(topic, "budget.finished", map[string]any{"campaign_id": id, "budget": b, "scenario_recall": p.ScenarioRecall, "detected": p.Detected})
	}
	fin := a.now()
	dur := time.Since(start).Milliseconds()
	if err := a.Store.UpdateCampaign(ctx, id, "succeeded", &fin, &dur, nil); err != nil {
		return err
	}
	_, _ = a.audit(ctx, a.Store, "system", "campaign.finished", id, map[string]any{"strategy": c.Strategy, "mitigated": c.Mitigated, "duration_ms": dur})
	a.Pub.Publish(topic, "done", map[string]any{"campaign_id": id})
	a.Pub.Close(topic)
	a.notify("campaign.finished", map[string]any{"campaign_id": id, "dataset_id": c.BaseDataset})
	return nil
}

// floodTarget is the highest-criticality sensitive asset: where a decoy flood
// does the most damage to the ranking.
func floodTarget(assets map[string]domain.Asset) string {
	best, crit := "", 0
	for h, as := range assets {
		if as.Criticality >= 9 && as.Sensitive() && (as.Criticality > crit || (as.Criticality == crit && h < best)) {
			best, crit = h, as.Criticality
		}
	}
	return best
}

func alertOrder(as []domain.Alert) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

func (a *App) GetCampaign(ctx context.Context, id string) (CampaignDetailView, error) {
	c, err := a.Store.GetCampaign(ctx, id)
	if err != nil {
		return CampaignDetailView{}, err
	}
	rs, err := a.Store.EvasionResults(ctx, id)
	if err != nil {
		return CampaignDetailView{}, err
	}
	if rs == nil {
		rs = []EvasionResult{}
	}
	v := CampaignDetailView{CampaignView: campaignView(c), Results: rs, Error: c.Error}
	if c.DurationMS != nil {
		v.DurationMS = *c.DurationMS
	}
	return v, nil
}

type CurveSeries struct {
	Strategy       string    `json:"strategy"`
	Mitigated      bool      `json:"mitigated"`
	CampaignID     string    `json:"campaign_id"`
	Values         []float64 `json:"values"`
	CrossesFloorAt *float64  `json:"crosses_floor_at"`
}

type Curve struct {
	BaseDataset string        `json:"base_dataset"`
	Metric      string        `json:"metric"`
	Budgets     []float64     `json:"budgets"`
	Series      []CurveSeries `json:"series"`
	Floor       float64       `json:"floor"`
	FloorLabel  string        `json:"floor_label"`
	Note        string        `json:"note"`
}

// EvasionCurve builds the plot-ready curve from the latest succeeded
// campaign per (strategy, mitigated). Budgets are the union of every series';
// a series missing a budget is linearly interpolated from its own points.
func (a *App) EvasionCurve(ctx context.Context, base, metric string, floor float64) (Curve, error) {
	if _, err := a.Store.GetDataset(ctx, base); err != nil {
		return Curve{}, err
	}
	if metric == "" {
		metric = "scenario_recall"
	}
	cs, err := a.Store.ListCampaigns(ctx, base, 500, nil, "")
	if err != nil {
		return Curve{}, err
	}
	type key struct {
		s string
		m bool
	}
	latest := map[key]Campaign{}
	for _, c := range cs { // newest first
		k := key{c.Strategy, c.Mitigated}
		if _, ok := latest[k]; !ok && c.Status == "succeeded" {
			latest[k] = c
		}
	}
	budgetSet := map[float64]bool{}
	points := map[key][][2]float64{}
	for k, c := range latest {
		rs, err := a.Store.EvasionResults(ctx, c.CampaignID)
		if err != nil {
			return Curve{}, err
		}
		for _, r := range rs {
			v := r.ScenarioRecall
			switch metric {
			case "pairwise_recall":
				v = r.PairwiseRecall
			case "pairwise_precision":
				v = r.PairwisePrecision
			}
			points[k] = append(points[k], [2]float64{r.Budget, v})
			budgetSet[r.Budget] = true
		}
	}
	out := Curve{BaseDataset: base, Metric: metric, Floor: floor, FloorLabel: "acceptable detection floor", Series: []CurveSeries{},
		Note: "recall is measured over the scenarios detected at β=0 with each campaign's configuration"}
	for b := range budgetSet {
		out.Budgets = append(out.Budgets, b)
	}
	sort.Float64s(out.Budgets)
	if out.Budgets == nil {
		out.Budgets = []float64{}
	}
	for _, s := range evade.Strategies {
		for _, m := range []bool{false, true} {
			k := key{s, m}
			pts, ok := points[k]
			if !ok {
				continue
			}
			sort.Slice(pts, func(i, j int) bool { return pts[i][0] < pts[j][0] })
			series := CurveSeries{Strategy: s, Mitigated: m, CampaignID: latest[k].CampaignID}
			for _, b := range out.Budgets {
				series.Values = append(series.Values, interpolate(pts, b))
			}
			series.CrossesFloorAt = evade.CrossesFloor(out.Budgets, series.Values, floor)
			out.Series = append(out.Series, series)
		}
	}
	return out, nil
}

func interpolate(pts [][2]float64, x float64) float64 {
	if x <= pts[0][0] {
		return pts[0][1]
	}
	for i := 1; i < len(pts); i++ {
		if x <= pts[i][0] {
			x0, y0, x1, y1 := pts[i-1][0], pts[i-1][1], pts[i][0], pts[i][1]
			if x1 == x0 {
				return y1
			}
			return math.Round((y0+(x-x0)*(y1-y0)/(x1-x0))*100) / 100
		}
	}
	return pts[len(pts)-1][1]
}

// ---------- evaluation ----------

type EvaluationView struct {
	EvaluationID string          `json:"evaluation_id"`
	RunID        string          `json:"run_id"`
	DatasetID    string          `json:"dataset_id"`
	CreatedAt    time.Time       `json:"created_at"`
	AnalystModel json.RawMessage `json:"analyst_model"`
	Baseline     string          `json:"baseline"`
	Metrics      json.RawMessage `json:"metrics"`
	Scenarios    json.RawMessage `json:"scenarios"`
}

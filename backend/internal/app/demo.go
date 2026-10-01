package app

import (
	"context"
	"fmt"
	"time"

	"prahari/internal/core/evade"
	"prahari/internal/core/evaluate"
	"prahari/internal/domain"
)

// prewarmDemo makes a fresh demo database show measured numbers, not empty
// panels: it scores the seed-42 run against its truth and runs the adversary
// bench for every strategy with and without the laundering pass, so the curve
// carries its mitigation overlay. Work already done is skipped, so a restart
// costs nothing. Campaigns go one at a time because the queue holds two.
func (a *App) prewarmDemo(ctx context.Context, datasetID, runID string) error {
	if err := a.waitRun(ctx, runID); err != nil {
		return err
	}

	if _, err := a.Store.LatestEvaluation(ctx, datasetID); err != nil {
		if de, ok := domain.AsError(err); !ok || de.Code != "NOT_FOUND" {
			return err
		}
		if _, err := a.Evaluate(ctx, runID, evaluate.AnalystModel{}, "system"); err != nil {
			return fmt.Errorf("evaluate: %w", err)
		}
	}

	existing, err := a.Store.ListCampaigns(ctx, datasetID, 500, nil, "")
	if err != nil {
		return err
	}
	done := map[string]bool{}
	for _, c := range existing {
		if c.Status == "succeeded" || c.Status == "queued" || c.Status == "running" {
			done[campaignKey(c.Strategy, c.Mitigated)] = true
		}
	}
	ran := 0
	for _, s := range evade.Strategies {
		for _, mitigated := range []bool{false, true} {
			if done[campaignKey(s, mitigated)] {
				continue
			}
			c, err := a.CreateCampaign(ctx, CampaignInput{BaseDataset: datasetID, Strategy: s, Mitigated: mitigated, Seed: 42}, "system")
			if err != nil {
				return fmt.Errorf("campaign %s: %w", campaignKey(s, mitigated), err)
			}
			if err := a.waitCampaign(ctx, c.CampaignID); err != nil {
				return err
			}
			ran++
		}
	}
	a.Log.Info("demo prewarmed", "dataset_id", datasetID, "campaigns_run", ran)
	return nil
}

func campaignKey(strategy string, mitigated bool) string {
	return fmt.Sprintf("%s/mitigated=%t", strategy, mitigated)
}

// waitRun polls until the run leaves the queue. Terminal states other than
// succeeded are errors: there is nothing to evaluate.
func (a *App) waitRun(ctx context.Context, runID string) error {
	return poll(ctx, 2*time.Minute, func() (bool, error) {
		r, err := a.Store.GetRun(ctx, runID)
		if err != nil {
			return false, err
		}
		switch r.Status {
		case "succeeded":
			return true, nil
		case "failed", "cancelled":
			return false, fmt.Errorf("run %s %s", runID, r.Status)
		}
		return false, nil
	})
}

func (a *App) waitCampaign(ctx context.Context, id string) error {
	return poll(ctx, 5*time.Minute, func() (bool, error) {
		c, err := a.Store.GetCampaign(ctx, id)
		if err != nil {
			return false, err
		}
		switch c.Status {
		case "succeeded":
			return true, nil
		case "failed":
			msg := ""
			if c.Error != nil {
				msg = *c.Error
			}
			return false, fmt.Errorf("campaign %s failed: %s", id, msg)
		}
		return false, nil
	})
}

func poll(ctx context.Context, limit time.Duration, check func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		ok, err := check()
		if err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

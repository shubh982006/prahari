package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/evade"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

func cmdAdversary(args []string) error {
	fs := flag.NewFlagSet("adversary", flag.ExitOnError)
	var c common
	c.register(fs)
	strategy := fs.String("strategy", "all", "strategy or all")
	budgetsFlag := fs.String("budgets", "0,0.25,0.5,0.75,1", "budgets")
	seedsFlag := fs.String("seeds", "1-5", "base dataset seeds")
	_ = fs.Parse(args)
	seeds, err := parseRange(*seedsFlag)
	if err != nil {
		return err
	}
	var budgets []float64
	for _, b := range strings.Split(*budgetsFlag, ",") {
		v, err := strconv.ParseFloat(b, 64)
		if err != nil {
			return err
		}
		budgets = append(budgets, v)
	}
	strategies := evade.Strategies
	if *strategy != "all" {
		strategies = []string{*strategy}
	}
	cat, err := attack.LoadFile(c.bundle)
	if err != nil {
		return err
	}
	fmt.Printf("scenario recall over scenarios detected at β=0, mean of %d seeds (top rank of scenario A in brackets)\n", len(seeds))
	fmt.Printf("%-22s %-5s", "strategy", "mitig")
	for _, b := range budgets {
		fmt.Printf("  β=%-10.2f", b)
	}
	fmt.Println()
	for _, s := range strategies {
		for _, mitigated := range []bool{false, true} {
			pts, err := benchCurve(cat, c, s, mitigated, seeds, budgets)
			if err != nil {
				return err
			}
			fmt.Printf("%-22s %-5v", s, mitigated)
			for _, p := range pts {
				ranks := make([]string, len(p.Ranks))
				for i, r := range p.Ranks {
					ranks[i] = "-"
					if r != nil {
						ranks[i] = strconv.Itoa(*r)
					}
				}
				fmt.Printf("  %.2f [%s]", p.Recall, strings.Join(ranks, ","))
			}
			fmt.Println()
		}
	}
	return nil
}

// benchPoint is one budget of a strategy, aggregated over seeds.
type benchPoint struct {
	Budget   float64
	Recall   float64 // mean scenario recall over seeds
	Detected int     // seeds on which the flagship scenario was still detected
	Ranks    []*int  // flagship rank per seed, nil when missed
}

// benchCurve runs one strategy at each budget over each seed, exactly as the
// campaign worker does: recall over the scenarios detected at β=0 under the
// same configuration.
func benchCurve(cat *attack.Catalog, c common, strategy string, mitigated bool, seeds []int64, budgets []float64) ([]benchPoint, error) {
	cfg := c.config()
	cfg.LaunderingPass = mitigated
	run := func(id string, alerts []domain.Alert) ([]domain.Incident, error) {
		out, err := correlate.Run(baseInput(cat, id, alerts, cfg), correlate.Hooks{})
		return out.Incidents, err
	}
	order := func(as []domain.Alert) []string {
		o := make([]string, len(as))
		for i, a := range as {
			o[i] = a.ID
		}
		return o
	}
	params := evade.Params{LinkWindow: cfg.LinkWindow, SupernodeRatio: cfg.SupernodeRatio, SupernodeMinDF: cfg.SupernodeMinDF, FloodTarget: "pay-db-01"}
	pts := make([]benchPoint, len(budgets))
	for i, b := range budgets {
		pts[i].Budget = b
	}
	for _, seed := range seeds {
		sim := simulate.Generate(simulate.Params{Seed: seed})
		base := sim.All()
		incs, err := run(sim.DatasetID, base)
		if err != nil {
			return nil, err
		}
		consider := evade.Baseline(incs, sim.Truth, order(base))
		for i, b := range budgets {
			v, err := evade.Generate(base, sim.Truth, strategy, b, seed, params, "ds_adv")
			if err != nil {
				return nil, err
			}
			incs, err := run("ds_adv", v.Alerts)
			if err != nil {
				return nil, err
			}
			p := evade.Score(b, incs, v.Truth, consider, order(v.Alerts))
			pts[i].Recall += p.ScenarioRecall
			if p.Detected {
				pts[i].Detected++
			}
			pts[i].Ranks = append(pts[i].Ranks, p.TopRank)
		}
	}
	for i := range pts {
		pts[i].Recall /= float64(len(seeds))
	}
	return pts, nil
}

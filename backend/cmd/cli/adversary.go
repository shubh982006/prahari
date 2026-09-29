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
	run := func(id string, alerts []domain.Alert, mitigated bool) []domain.Incident {
		cfg := c.config()
		cfg.LaunderingPass = mitigated
		out, err := correlate.Run(baseInput(cat, id, alerts, cfg), correlate.Hooks{})
		if err != nil {
			panic(err)
		}
		return out.Incidents
	}
	order := func(as []domain.Alert) []string {
		o := make([]string, len(as))
		for i, a := range as {
			o[i] = a.ID
		}
		return o
	}
	fmt.Printf("scenario recall over scenarios detected at β=0, mean of %d seeds (top rank of scenario A in brackets)\n", len(seeds))
	fmt.Printf("%-22s %-5s", "strategy", "mitig")
	for _, b := range budgets {
		fmt.Printf("  β=%-10.2f", b)
	}
	fmt.Println()
	for _, s := range strategies {
		for _, mitigated := range []bool{false, true} {
			sum := make([]float64, len(budgets))
			ranks := make([][]string, len(budgets))
			for _, seed := range seeds {
				sim := simulate.Generate(simulate.Params{Seed: seed})
				base := sim.All()
				consider := evade.Baseline(run(sim.DatasetID, base, mitigated), sim.Truth, order(base))
				for i, b := range budgets {
					v, err := evade.Generate(base, sim.Truth, s, b, seed, evade.Params{LinkWindow: c.window, SupernodeRatio: 0.05, SupernodeMinDF: 20, FloodTarget: "pay-db-01"}, "ds_adv")
					if err != nil {
						return err
					}
					p := evade.Score(b, run("ds_adv", v.Alerts, mitigated), v.Truth, consider, order(v.Alerts))
					sum[i] += p.ScenarioRecall
					r := "-"
					if p.TopRank != nil {
						r = strconv.Itoa(*p.TopRank)
					}
					ranks[i] = append(ranks[i], r)
				}
			}
			fmt.Printf("%-22s %-5v", s, mitigated)
			for i := range budgets {
				fmt.Printf("  %.2f [%s]", sum[i]/float64(len(seeds)), strings.Join(ranks[i], ","))
			}
			fmt.Println()
		}
	}
	return nil
}

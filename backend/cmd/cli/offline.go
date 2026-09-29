package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/core/evaluate"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

const defaultBundle = "data/attack/enterprise-attack-19.0.min.json"

type common struct {
	bundle    string
	window    time.Duration
	noLaunder bool
	bandMode  string
	noise     string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.bundle, "attack", defaultBundle, "ATT&CK STIX bundle")
	fs.DurationVar(&c.window, "window", 2*time.Hour, "link window")
	fs.BoolVar(&c.noLaunder, "no-launder", false, "disable the laundering pass")
	fs.StringVar(&c.bandMode, "bands", "calibrated", "calibrated | fixed")
	fs.StringVar(&c.noise, "noise", "normal", "low | normal | high")
}

func (c *common) config() correlate.Config {
	cfg := correlate.DefaultConfig()
	cfg.LinkWindow = c.window
	cfg.LaunderingPass = !c.noLaunder
	cfg.BandMode = c.bandMode
	return cfg
}

func parseRange(s string) ([]int64, error) {
	var out []int64
	for _, part := range strings.Split(s, ",") {
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, err1 := strconv.ParseInt(a, 10, 64)
			hi, err2 := strconv.ParseInt(b, 10, 64)
			if err1 != nil || err2 != nil || hi < lo {
				return nil, fmt.Errorf("bad range %q", part)
			}
			for v := lo; v <= hi; v++ {
				out = append(out, v)
			}
			continue
		}
		v, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad seed %q", part)
		}
		out = append(out, v)
	}
	return out, nil
}

func cmdEvaluate(args []string) error {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	var c common
	c.register(fs)
	seedsFlag := fs.String("seeds", "1-10", "seed list or range")
	perSeed := fs.Bool("v", false, "print each seed")
	_ = fs.Parse(args)
	seeds, err := parseRange(*seedsFlag)
	if err != nil {
		return err
	}
	cat, err := attack.LoadFile(c.bundle)
	if err != nil {
		return err
	}
	cols := []string{"compression_ratio", "scenario_recall", "pairwise_precision", "pairwise_recall",
		"mean_purity", "precision_at_5", "cohesion_accuracy", "noise_in_top10", "triage_time_reduction", "correlate_ms"}
	vals := map[string][]float64{}
	detected := map[string]int{}
	for _, s := range seeds {
		r, err := runInMemory(cat, simulate.Params{Seed: s, NoiseLevel: c.noise}, c.config())
		if err != nil {
			return err
		}
		mm := metricMap(r.metrics)
		for _, k := range cols {
			vals[k] = append(vals[k], mm[k])
		}
		for _, sc := range r.scen {
			if sc.Detected {
				detected[sc.Scenario]++
			}
		}
		if *perSeed {
			fmt.Printf("seed %d: %d alerts → %d incidents, recall %.2f, P@5 %.2f, fragile %d (acc %.2f), %dms\n",
				s, len(r.alerts), len(r.out.Incidents), r.metrics.ScenarioRecall, r.metrics.PrecisionAt5,
				r.metrics.FragileIncidents, r.metrics.CohesionAccuracy, r.metrics.CorrelateMS)
		}
	}
	fmt.Printf("seeds %s · window %s · laundering %v · bands %s · noise %s\n", *seedsFlag, c.window, !c.noLaunder, c.bandMode, c.noise)
	fmt.Println(evaluate.Baseline(evaluate.DefaultAnalyst))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "metric\tmean\tstd\tmin\tmax")
	for _, k := range cols {
		m, sd, lo, hi := stats(vals[k])
		fmt.Fprintf(tw, "%s\t%.2f\t%.2f\t%.2f\t%.2f\n", k, m, sd, lo, hi)
	}
	tw.Flush()
	fmt.Print("scenarios detected (of ", len(seeds), " seeds): ")
	for _, s := range simulate.AllScenarios {
		fmt.Printf("%s %d  ", s, detected[s])
	}
	fmt.Println()
	return nil
}

func metricMap(m evaluate.Metrics) map[string]float64 {
	b, _ := json.Marshal(m)
	out := map[string]float64{}
	_ = json.Unmarshal(b, &out)
	return out
}

func stats(xs []float64) (mean, sd, lo, hi float64) {
	if len(xs) == 0 {
		return
	}
	lo, hi = xs[0], xs[0]
	for _, x := range xs {
		mean += x
		lo, hi = math.Min(lo, x), math.Max(hi, x)
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		sd += (x - mean) * (x - mean)
	}
	if len(xs) > 1 {
		sd = math.Sqrt(sd / float64(len(xs)-1))
	}
	return
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	var c common
	c.register(fs)
	seed := fs.Int64("seed", 42, "seed")
	top := fs.Int("top", 20, "incidents to print")
	_ = fs.Parse(args)
	cat, err := attack.LoadFile(c.bundle)
	if err != nil {
		return err
	}
	r, err := runInMemory(cat, simulate.Params{Seed: *seed, NoiseLevel: c.noise}, c.config())
	if err != nil {
		return err
	}
	lbl := map[string]int{}
	coh := map[string]int{}
	pri := map[string]int{}
	for _, inc := range r.out.Incidents {
		lbl[inc.Label]++
		coh[inc.Cohesion]++
		pri[inc.Priority]++
	}
	fmt.Printf("%s\n%d alerts → %d incidents in %s · bands %+v\nlabels %v · cohesion %v · priority %v\nstop-list %v · laundered links %d\n\n",
		r.sim.Summary(), len(r.alerts), len(r.out.Incidents), r.elapsed.Round(time.Millisecond), r.out.Bands, lbl, coh, pri,
		r.out.Stoplist, r.out.LaunderingLinks)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tid\tpri\trisk\tC\tS\tA\tQ\tlabel\tcoh\tn\ttruth\theadline")
	for i, inc := range r.out.Incidents {
		if i == *top {
			break
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%s\t%s\t%d\t%s\t%s\n", inc.Rank, inc.ID, inc.Priority, inc.Risk,
			inc.Breakdown.C, inc.Breakdown.S, inc.Breakdown.A, inc.Breakdown.Q, inc.Label, inc.Cohesion, len(inc.AlertIDs),
			truthMix(inc, r.sim.Truth), trunc(inc.Headline, 70))
	}
	tw.Flush()
	fmt.Println()
	for _, s := range r.scen {
		rank, pr, miss := "-", "-", ""
		if s.Rank != nil {
			rank = strconv.Itoa(*s.Rank)
		}
		if s.ActualPriority != nil {
			pr = *s.ActualPriority
		}
		if s.MissReason != nil {
			miss = *s.MissReason
		}
		fmt.Printf("scenario %s detected=%v coverage=%.2f rank=%s priority=%s (expected %s) %s\n", s.Scenario, s.Detected, s.Coverage, rank, pr, s.ExpectedPriority, miss)
	}
	b, _ := json.MarshalIndent(r.metrics, "", "  ")
	fmt.Println(string(b))
	for _, inc := range r.out.Incidents {
		if inc.Cohesion == "fragile" {
			fmt.Printf("fragile %s: %s | left %d (%s) right %d (%s)\n", inc.ID, inc.CohesionReason,
				inc.SplitPreview.Left.Alerts, inc.SplitPreview.Left.EstPriority, inc.SplitPreview.Right.Alerts, inc.SplitPreview.Right.EstPriority)
		}
	}
	return nil
}

func truthMix(inc domain.Incident, t domain.Truth) string {
	c := map[string]int{}
	for _, a := range inc.AlertIDs {
		g := t.Groups[a]
		if strings.HasPrefix(g, "noise:burst") {
			g = "burst"
		}
		c[g]++
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return c[keys[i]] > c[keys[j]] })
	var parts []string
	for i, k := range keys {
		if i == 3 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", strings.TrimPrefix(k, "noise:"), c[k]))
	}
	return strings.Join(parts, " ")
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func cmdSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	seed := fs.Int64("seed", 42, "seed")
	outDir := fs.String("out", "out", "output directory")
	noise := fs.String("noise", "normal", "low | normal | high")
	users := fs.Int("users", 60, "users")
	_ = fs.Parse(args)
	r := simulate.Generate(simulate.Params{Seed: *seed, NoiseLevel: *noise, Users: *users})
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	write := func(name string, rows func(func(any))) error {
		f, err := os.Create(filepath.Join(*outDir, name))
		if err != nil {
			return err
		}
		defer f.Close()
		w := bufio.NewWriter(f)
		enc := json.NewEncoder(w)
		rows(func(v any) { _ = enc.Encode(v) })
		return w.Flush()
	}
	if err := write(r.DatasetID+".auth-events.ndjson", func(emit func(any)) {
		for _, e := range r.AuthEvents {
			e.DatasetID = ""
			emit(e)
		}
	}); err != nil {
		return err
	}
	if err := write(r.DatasetID+".alerts.ndjson", func(emit func(any)) {
		for _, a := range r.Alerts {
			a.DatasetID = ""
			emit(a)
		}
	}); err != nil {
		return err
	}
	tb, _ := json.MarshalIndent(r.Truth, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, r.DatasetID+".truth.json"), tb, 0o644); err != nil {
		return err
	}
	fmt.Println(r.Summary())
	return nil
}

func cmdCMDB(args []string) error {
	b, _ := json.MarshalIndent(simulate.CMDB(), "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	var c common
	c.register(fs)
	sizes := fs.String("sizes", "3000,50000,300000", "alert counts")
	_ = fs.Parse(args)
	cat, err := attack.LoadFile(c.bundle)
	if err != nil {
		return err
	}
	fmt.Println("alerts\tincidents\tcorrelate_ms\talloc_mb")
	for _, part := range strings.Split(*sizes, ",") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return err
		}
		alerts := scaledAlerts(n)
		in := baseInput(cat, "ds_bench", alerts, c.config())
		var before, after runtimeMem
		before.read()
		start := time.Now()
		out, err := correlate.Run(in, correlate.Hooks{})
		if err != nil {
			return err
		}
		el := time.Since(start)
		after.read()
		fmt.Printf("%d\t%d\t%d\t%.0f\n", len(alerts), len(out.Incidents), el.Milliseconds(), after.peakMB(before))
	}
	return nil
}

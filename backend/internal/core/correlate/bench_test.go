package correlate_test

import (
	"fmt"
	"testing"
	"time"

	"prahari/internal/core/correlate"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

// scaled builds n alerts by laying simulated days end to end, each with its
// own seed, so linking sees realistic density at every size (as cli bench).
func scaled(n int) []domain.Alert {
	out := make([]domain.Alert, 0, n)
	for day := 0; len(out) < n; day++ {
		r := simulate.Generate(simulate.Params{Seed: int64(1000 + day), Start: simulate.DefaultStart.Add(time.Duration(day) * 24 * time.Hour)})
		for _, a := range r.All() {
			a.ID = fmt.Sprintf("D%d-%s", day, a.ID)
			out = append(out, a)
			if len(out) == n {
				break
			}
		}
	}
	return out
}

// BenchmarkRun times the whole pure engine (filter → compliance) at the
// design's sizes. Dataset generation is excluded. NFR-1 targets 3k alerts in
// under 500 ms p95.
//
//	go test ./internal/core/correlate -run '^$' -bench Run -benchmem
func BenchmarkRun(b *testing.B) {
	for _, n := range []int{3_000, 50_000, 300_000} {
		b.Run(fmt.Sprintf("alerts=%d", n), func(b *testing.B) {
			in := input(scaled(n), correlate.DefaultConfig())
			b.ReportAllocs()
			b.ResetTimer()
			var incidents int
			for i := 0; i < b.N; i++ {
				out, err := correlate.Run(in, correlate.Hooks{})
				if err != nil {
					b.Fatal(err)
				}
				incidents = len(out.Incidents)
			}
			b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds(), "alerts/s")
			b.ReportMetric(float64(incidents), "incidents")
		})
	}
}

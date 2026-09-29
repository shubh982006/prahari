package main

import (
	"fmt"
	"runtime"
	"time"

	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

// scaledAlerts builds n alerts by laying simulated days end to end, each day
// with its own seed, so linking still sees realistic density.
func scaledAlerts(n int) []domain.Alert {
	var out []domain.Alert
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

type runtimeMem struct{ total uint64 }

func (m *runtimeMem) read() {
	var s runtime.MemStats
	runtime.ReadMemStats(&s)
	m.total = s.TotalAlloc
}

// peakMB reports bytes allocated between two readings, an upper bound on the
// working set of the run.
func (m runtimeMem) peakMB(before runtimeMem) float64 {
	return float64(m.total-before.total) / (1 << 20)
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

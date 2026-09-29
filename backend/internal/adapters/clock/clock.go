// Package clock provides the system clock and a settable one for tests.
package clock

import (
	"sync"
	"time"
)

type System struct{}

func (System) Now() time.Time { return time.Now().UTC() }

// Fixed is a clock tests can move.
type Fixed struct {
	mu sync.Mutex
	t  time.Time
}

func NewFixed(t time.Time) *Fixed { return &Fixed{t: t} }

func (f *Fixed) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *Fixed) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

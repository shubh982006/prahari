// Package inproc is the single-instance event bus: a mutex-guarded subscriber
// map with a replay ring per topic for Last-Event-ID resume. A slow consumer
// is dropped rather than allowed to block the publisher; it reconnects and
// replays.
package inproc

import (
	"encoding/json"
	"strconv"
	"sync"

	"prahari/internal/app"
)

const (
	RingSize  = 200
	SubBuffer = 64
	maxTopics = 1000
)

type topic struct {
	name   string
	ring   []app.Event
	subs   map[int]chan app.Event
	closed bool
	seq    int64
}

type Broker struct {
	mu     sync.Mutex
	topics map[string]*topic
	order  []string // creation order, for evicting old closed topics
	nextID int
}

var _ app.Publisher = (*Broker)(nil)

func New() *Broker { return &Broker{topics: map[string]*topic{}} }

func (b *Broker) get(name string) *topic {
	t, ok := b.topics[name]
	if !ok {
		t = &topic{name: name, subs: map[int]chan app.Event{}}
		b.topics[name] = t
		b.order = append(b.order, name)
		b.evict()
	}
	return t
}

func (b *Broker) evict() {
	for len(b.topics) > maxTopics && len(b.order) > 0 {
		evicted := false
		for i, name := range b.order {
			if t := b.topics[name]; t != nil && t.closed {
				delete(b.topics, name)
				b.order = append(b.order[:i], b.order[i+1:]...)
				evicted = true
				break
			}
		}
		if !evicted {
			return
		}
	}
}

// NextID reserves the next event ID for a topic; pgnotify uses it so every
// instance agrees on IDs.
func (b *Broker) NextID(name string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.get(name)
	t.seq++
	return strconv.FormatInt(t.seq, 10)
}

func (b *Broker) Publish(name, typ string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	b.mu.Lock()
	t := b.get(name)
	t.seq++
	ev := app.Event{ID: strconv.FormatInt(t.seq, 10), Topic: name, Type: typ, Data: raw}
	b.deliverLocked(t, ev)
	b.mu.Unlock()
}

// Deliver injects an already-identified event (from another instance).
func (b *Broker) Deliver(ev app.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.get(ev.Topic)
	if n, err := strconv.ParseInt(ev.ID, 10, 64); err == nil && n > t.seq {
		t.seq = n
	}
	b.deliverLocked(t, ev)
}

func (b *Broker) deliverLocked(t *topic, ev app.Event) {
	if t.closed {
		return
	}
	t.ring = append(t.ring, ev)
	if len(t.ring) > RingSize {
		t.ring = t.ring[len(t.ring)-RingSize:]
	}
	for id, ch := range t.subs {
		select {
		case ch <- ev:
		default: // slow consumer: drop it, it will resume with Last-Event-ID
			close(ch)
			delete(t.subs, id)
		}
	}
}

func (b *Broker) Subscribe(name, lastID string) ([]app.Event, <-chan app.Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.get(name)
	var replay []app.Event
	start := 0
	if lastID != "" {
		for i, ev := range t.ring {
			if ev.ID == lastID {
				start = i + 1
			}
		}
	}
	replay = append(replay, t.ring[start:]...)
	ch := make(chan app.Event, SubBuffer)
	if t.closed {
		close(ch)
		return replay, ch, func() {}
	}
	b.nextID++
	id := b.nextID
	t.subs[id] = ch
	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if c, ok := t.subs[id]; ok {
			close(c)
			delete(t.subs, id)
		}
	}
	return replay, ch, cancel
}

// Close marks a topic finished: current subscribers' channels close after the
// last event, and later subscribers get the replay and an already-closed
// channel.
func (b *Broker) Close(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.get(name)
	if t.closed {
		return
	}
	t.closed = true
	for id, ch := range t.subs {
		close(ch)
		delete(t.subs, id)
	}
}

func (b *Broker) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, t := range b.topics {
		n += len(t.subs)
	}
	return n
}

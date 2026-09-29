// Package pgnotify is the multi-instance event bus. Every instance publishes
// with NOTIFY and fans out from a single LISTEN connection into its local
// in-process broker, which keeps the replay ring. This is what removes the
// single-instance constraint on Postgres.
package pgnotify

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"prahari/internal/adapters/broker/inproc"
	"prahari/internal/app"
)

const channel = "prahari_events"

// NOTIFY payloads are capped at 8000 bytes; an event that would not fit is
// sent without data and clients refetch.
const maxPayload = 7900

type wire struct {
	ID    string          `json:"i"`
	Topic string          `json:"t"`
	Type  string          `json:"y"`
	Data  json.RawMessage `json:"d,omitempty"`
	Close bool            `json:"c,omitempty"`
}

type Broker struct {
	local *inproc.Broker
	dsn   string
	pub   *pgx.Conn
	log   *slog.Logger
	out   chan wire
}

var _ app.Publisher = (*Broker)(nil)

func New(ctx context.Context, dsn string, log *slog.Logger) (*Broker, error) {
	pub, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	b := &Broker{local: inproc.New(), dsn: dsn, pub: pub, log: log, out: make(chan wire, 1024)}
	go b.listen(ctx)
	go b.send(ctx)
	return b, nil
}

func (b *Broker) listen(ctx context.Context) {
	for ctx.Err() == nil {
		conn, err := pgx.Connect(ctx, b.dsn)
		if err != nil {
			b.log.Warn("pgnotify connect", "err", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
			conn.Close(ctx)
			continue
		}
		for {
			n, err := conn.WaitForNotification(ctx)
			if err != nil {
				break
			}
			var w wire
			if json.Unmarshal([]byte(n.Payload), &w) != nil {
				continue
			}
			if w.Close {
				b.local.Close(w.Topic)
				continue
			}
			b.local.Deliver(app.Event{ID: w.ID, Topic: w.Topic, Type: w.Type, Data: w.Data})
		}
		conn.Close(context.Background())
	}
}

// send serialises NOTIFYs on one connection; pgx connections are not safe
// for concurrent use.
func (b *Broker) send(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case w := <-b.out:
			p, _ := json.Marshal(w)
			if len(p) > maxPayload {
				w.Data = nil
				p, _ = json.Marshal(w)
			}
			if _, err := b.pub.Exec(ctx, "SELECT pg_notify($1, $2)", channel, string(p)); err != nil {
				b.log.Warn("pgnotify publish", "err", err)
			}
		}
	}
}

func (b *Broker) Publish(topic, typ string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	b.out <- wire{ID: b.local.NextID(topic), Topic: topic, Type: typ, Data: raw}
}

func (b *Broker) Subscribe(topic, lastID string) ([]app.Event, <-chan app.Event, func()) {
	return b.local.Subscribe(topic, lastID)
}

func (b *Broker) Close(topic string) { b.out <- wire{Topic: topic, Close: true} }

func (b *Broker) Subscribers() int { return b.local.Subscribers() }

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"prahari/internal/app"
	"prahari/internal/domain"
)

const pingEvery = 15 * time.Second

// stream writes Server-Sent Events: a retry hint, the replay after
// Last-Event-ID, then live events with a ping comment every 15 s. It returns
// when the topic closes, the subscriber is dropped for being slow, or the
// client goes away. synth supplies events for a finished topic whose replay
// ring is gone (for example after a restart).
func (s *Server) stream(w http.ResponseWriter, r *http.Request, topic string, replayAll bool, synth func(ctx context.Context) []app.Event) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, r, domain.E(500, "INTERNAL", "streaming unsupported"))
		return
	}
	last := r.Header.Get("Last-Event-ID")
	replay, ch, cancel := s.app.Pub.Subscribe(topic, last)
	defer cancel()
	if last == "" && !replayAll {
		replay = nil
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n")
	write := func(ev app.Event) {
		fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, ev.Data)
	}
	for _, ev := range replay {
		write(ev)
	}
	if len(replay) == 0 && synth != nil && last == "" {
		if evs := synth(r.Context()); len(evs) > 0 {
			for _, ev := range evs {
				write(ev)
			}
			fl.Flush()
			return
		}
	}
	fl.Flush()
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.closing:
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			write(ev)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func event(id, typ string, data any) app.Event {
	b, _ := json.Marshal(data)
	return app.Event{ID: id, Type: typ, Data: b}
}

func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("runId")
	if _, err := s.app.Store.GetRun(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	s.stream(w, r, app.RunTopic(id), true, func(ctx context.Context) []app.Event {
		run, err := s.app.Store.GetRun(ctx, id)
		if err != nil {
			return nil
		}
		switch run.Status {
		case "succeeded":
			return []app.Event{
				event("1", "status", map[string]any{"run_id": id, "status": "succeeded"}),
				event("2", "done", map[string]any{"run_id": id, "summary": json.RawMessage(run.Summary)}),
			}
		case "failed", "cancelled":
			msg := ""
			if run.Error != nil {
				msg = *run.Error
			}
			return []app.Event{
				event("1", "status", map[string]any{"run_id": id, "status": run.Status}),
				event("2", "error", map[string]any{"run_id": id, "code": "RUN_" + map[string]string{"failed": "FAILED", "cancelled": "CANCELLED"}[run.Status], "message": msg}),
			}
		}
		return nil
	})
}

func (s *Server) campaignEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("campaignId")
	if _, err := s.app.Store.GetCampaign(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	s.stream(w, r, app.CampaignTopic(id), true, func(ctx context.Context) []app.Event {
		c, err := s.app.GetCampaign(ctx, id)
		if err != nil {
			return nil
		}
		switch c.Status {
		case "succeeded":
			var evs []app.Event
			for i, res := range c.Results {
				evs = append(evs, event(fmt.Sprint(i+1), "budget.finished", map[string]any{"campaign_id": id, "budget": res.Budget,
					"scenario_recall": res.ScenarioRecall, "detected": res.Detected}))
			}
			return append(evs, event(fmt.Sprint(len(evs)+1), "done", map[string]any{"campaign_id": id}))
		case "failed":
			msg := ""
			if c.Error != nil {
				msg = *c.Error
			}
			return []app.Event{event("1", "error", map[string]any{"campaign_id": id, "code": "CAMPAIGN_FAILED", "message": msg})}
		}
		return nil
	})
}

func (s *Server) globalEvents(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, app.GlobalTopic, false, nil)
}

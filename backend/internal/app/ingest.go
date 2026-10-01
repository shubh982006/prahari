package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"prahari/internal/core/detect"
	"prahari/internal/core/entity"
	"prahari/internal/domain"
)

const (
	MaxLineBytes    = 1 << 20
	maxReportErrors = 50
	writeBatch      = 500
	flushEvery      = 250 * time.Millisecond
)

type IngestError struct {
	Line    int    `json:"line"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

type IngestReport struct {
	Received     int           `json:"received"`
	Accepted     int           `json:"accepted"`
	Rejected     int           `json:"rejected"`
	Duplicates   int           `json:"duplicates"`
	AlertsRaised int           `json:"alerts_raised"`
	LateEvents   int           `json:"late_events"`
	Errors       []IngestError `json:"errors"`
	DurationMS   int64         `json:"duration_ms"`
}

func (r *IngestReport) fail(e IngestError) {
	r.Rejected++
	if len(r.Errors) < maxReportErrors {
		r.Errors = append(r.Errors, e)
	}
}

var ErrLineTooLong = domain.E(413, "PAYLOAD_TOO_LARGE", "a line exceeds 1 MB; split the record")

type line struct {
	seq, n int // seq is gapless over non-blank lines; n is the file line number
	text   []byte
}

type parsed struct {
	seq   int
	n     int
	alert *domain.Alert
	event *domain.AuthEvent
	err   *IngestError
}

// pipeline reads NDJSON, parses on K workers, and hands results back in file
// order. Channels are bounded, so a slow sink stops the reader draining the
// request body: memory stays flat whatever the upload size. A cancelled
// context stops every stage.
func pipeline(ctx context.Context, body io.Reader, parse func(n int, b []byte) parsed, sink func(parsed) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lines := make(chan line, 1024)
	results := make(chan parsed, 1024)
	var readErr error
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 64*1024), MaxLineBytes+1)
		n, seq := 0, 0
		for sc.Scan() {
			n++
			b := sc.Bytes()
			if len(bytes.TrimSpace(b)) == 0 {
				continue
			}
			seq++
			select {
			case lines <- line{seq, n, append([]byte(nil), b...)}:
			case <-ctx.Done():
				return
			}
		}
		if err := sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				readErr = ErrLineTooLong
			} else {
				readErr = err
			}
			cancel()
		}
	}()
	var wg sync.WaitGroup
	for k := 0; k < runtime.GOMAXPROCS(0); k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range lines {
				p := parse(l.n, l.text)
				p.seq = l.seq
				select {
				case results <- p:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	// Re-sequence: parsers finish out of order, detectors need file order.
	pending := map[int]parsed{}
	next := 1
	var sinkErr error
	for p := range results {
		pending[p.seq] = p
		for {
			q, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			if sinkErr == nil {
				if err := sink(q); err != nil {
					sinkErr = err
					cancel()
				}
			}
		}
	}
	if readErr != nil {
		return readErr
	}
	if sinkErr != nil {
		return sinkErr
	}
	return ctx.Err()
}

// ---------- alerts ----------

var (
	techniqueRe = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	hashRe      = regexp.MustCompile(`^[A-Fa-f0-9]{32,64}$`)
	sources     = map[string]bool{"auth": true, "edr": true, "network": true, "cloud": true, "email": true}
)

type alertIn struct {
	ID          *string          `json:"id"`
	Timestamp   *string          `json:"timestamp"`
	Source      *string          `json:"source"`
	RuleID      *string          `json:"rule_id"`
	RuleName    *string          `json:"rule_name"`
	Severity    *string          `json:"severity"`
	TechniqueID *string          `json:"technique_id"`
	Entities    *domain.Entities `json:"entities"`
	Raw         json.RawMessage  `json:"raw"`
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON object")
	}
	return nil
}

func decodeMessage(err error) (string, string) {
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field ") {
		f := strings.Trim(strings.TrimPrefix(msg, "json: unknown field "), `"`)
		return f, "unknown field"
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return te.Field, "wrong type: expected " + te.Type.String()
	}
	return "", "invalid JSON: " + msg
}

// ParseAlert validates one AlertInput line against the frozen schema.
func ParseAlert(datasetID string, n int, b []byte) parsed {
	bad := func(field, msg string) parsed {
		return parsed{n: n, err: &IngestError{Line: n, Field: field, Message: msg}}
	}
	var in alertIn
	if err := strictDecode(b, &in); err != nil {
		f, m := decodeMessage(err)
		return bad(f, m)
	}
	req := func(p *string, field string, max int) (string, *parsed) {
		if p == nil || *p == "" {
			r := bad(field, "is required")
			return "", &r
		}
		if len(*p) > max {
			r := bad(field, fmt.Sprintf("must be at most %d characters", max))
			return "", &r
		}
		return *p, nil
	}
	id, e := req(in.ID, "id", 64)
	if e != nil {
		return *e
	}
	tsS, e := req(in.Timestamp, "timestamp", 64)
	if e != nil {
		return *e
	}
	ts, err := time.Parse(time.RFC3339Nano, tsS)
	if err != nil {
		return bad("timestamp", "must be RFC 3339 date-time")
	}
	src, e := req(in.Source, "source", 16)
	if e != nil {
		return *e
	}
	if !sources[src] {
		return bad("source", "must be one of: auth, edr, network, cloud, email")
	}
	ruleID, e := req(in.RuleID, "rule_id", 64)
	if e != nil {
		return *e
	}
	ruleName, e := req(in.RuleName, "rule_name", 256)
	if e != nil {
		return *e
	}
	sevS, e := req(in.Severity, "severity", 16)
	if e != nil {
		return *e
	}
	sev := domain.Severity(sevS)
	if !sev.Valid() {
		return bad("severity", "must be one of: low, medium, high, critical")
	}
	tech := ""
	if in.TechniqueID != nil && *in.TechniqueID != "" {
		if !techniqueRe.MatchString(*in.TechniqueID) {
			return bad("technique_id", "must look like T1234 or T1234.001")
		}
		tech = *in.TechniqueID
	}
	if in.Entities == nil {
		return bad("entities", "is required")
	}
	ents := *in.Entities
	for field, xs := range map[string][]string{"users": ents.Users, "hosts": ents.Hosts, "ips": ents.IPs, "processes": ents.Processes, "hashes": ents.Hashes} {
		if len(xs) > 20 {
			return bad("entities."+field, "at most 20 items")
		}
		for _, x := range xs {
			if len(x) > 512 {
				return bad("entities."+field, "item too long")
			}
		}
	}
	for _, h := range ents.Hashes {
		if !hashRe.MatchString(h) {
			return bad("entities.hashes", "must be 32–64 hex characters")
		}
	}
	for _, ip := range ents.IPs {
		if _, err := netip.ParseAddr(strings.TrimSpace(ip)); err != nil {
			return bad("entities.ips", fmt.Sprintf("%q is not an IP address", ip))
		}
	}
	raw := in.Raw
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage("{}")
	} else if bytes.TrimSpace(raw)[0] != '{' {
		return bad("raw", "must be an object")
	}
	a := domain.Alert{DatasetID: datasetID, ID: id, TS: ts.UTC().Truncate(time.Microsecond), Source: src, RuleID: ruleID,
		RuleName: ruleName, Severity: sev, TechniqueID: tech, Entities: entity.Normalize(ents).Normalized(), Raw: raw}
	return parsed{n: n, alert: &a}
}

type authIn struct {
	EventID   *string `json:"event_id"`
	Timestamp *string `json:"timestamp"`
	Username  *string `json:"username"`
	SrcIP     *string `json:"src_ip"`
	Geo       *string `json:"geo"`
	Result    *string `json:"result"`
	App       *string `json:"app"`
	IsAdmin   *bool   `json:"is_admin"`
}

var apps = map[string]bool{"vpn": true, "o365": true, "rdp": true, "ssh": true, "web": true}

func ParseAuthEvent(datasetID string, n int, b []byte) parsed {
	bad := func(field, msg string) parsed {
		return parsed{n: n, err: &IngestError{Line: n, Field: field, Message: msg}}
	}
	var in authIn
	if err := strictDecode(b, &in); err != nil {
		f, m := decodeMessage(err)
		return bad(f, m)
	}
	get := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	e := domain.AuthEvent{DatasetID: datasetID, EventID: get(in.EventID), Username: get(in.Username), SrcIP: get(in.SrcIP),
		Geo: get(in.Geo), Result: get(in.Result), App: get(in.App)}
	switch {
	case e.EventID == "":
		return bad("event_id", "is required")
	case len(e.EventID) > 64:
		return bad("event_id", "must be at most 64 characters")
	case in.Timestamp == nil:
		return bad("timestamp", "is required")
	case e.Username == "" || len(e.Username) > 256:
		return bad("username", "is required, at most 256 characters")
	case e.SrcIP == "":
		return bad("src_ip", "is required")
	case e.Result != "success" && e.Result != "failure":
		return bad("result", "must be one of: success, failure")
	case !apps[e.App]:
		return bad("app", "must be one of: vpn, o365, rdp, ssh, web")
	}
	ts, err := time.Parse(time.RFC3339Nano, *in.Timestamp)
	if err != nil {
		return bad("timestamp", "must be RFC 3339 date-time")
	}
	if _, err := netip.ParseAddr(e.SrcIP); err != nil {
		return bad("src_ip", "must be an IPv4 or IPv6 address")
	}
	e.TS = ts.UTC().Truncate(time.Microsecond)
	if in.IsAdmin != nil {
		e.IsAdmin = *in.IsAdmin
	}
	return parsed{n: n, event: &e}
}

func (a *App) ingestTarget(ctx context.Context, datasetID string) (Dataset, error) {
	d, err := a.Store.GetDataset(ctx, datasetID)
	if err != nil {
		return d, err
	}
	if d.Kind == "adversarial" {
		return d, domain.Unprocessable("ADVERSARIAL_MIX", "dataset %s holds adversarial variants; real alerts cannot be added to it", datasetID)
	}
	return d, nil
}

// IngestAlerts streams NDJSON alerts into a dataset.
func (a *App) IngestAlerts(ctx context.Context, datasetID, actor string, body io.Reader) (IngestReport, error) {
	start := time.Now()
	rep := IngestReport{Errors: []IngestError{}}
	if _, err := a.ingestTarget(ctx, datasetID); err != nil {
		return rep, err
	}
	var batch []domain.Alert
	var lo, hi time.Time
	seenRules := map[string]bool{}
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// Rules first seen here start at Beta(1,1) with their real source, so
		// feedback on them is learned like any other rule's.
		var fresh []domain.RuleStat
		for _, al := range batch {
			if !seenRules[al.RuleID] {
				seenRules[al.RuleID] = true
				fresh = append(fresh, domain.RuleStat{RuleID: al.RuleID, RuleName: al.RuleName, Source: al.Source, TechniqueID: al.TechniqueID, Alpha: 1, Beta: 1})
			}
		}
		if err := a.Store.SeedRuleStats(ctx, fresh); err != nil {
			return err
		}
		ins, dup, err := a.Store.InsertAlerts(ctx, batch)
		if err != nil {
			return err
		}
		rep.Accepted += ins
		rep.Duplicates += dup
		if err := a.Store.AddDatasetCounts(ctx, datasetID, 0, ins, 0); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}
	lastFlush := time.Now()
	err := pipeline(ctx, body, func(n int, b []byte) parsed { return ParseAlert(datasetID, n, b) }, func(p parsed) error {
		rep.Received++
		if p.err != nil {
			rep.fail(*p.err)
			return nil
		}
		batch = append(batch, *p.alert)
		if lo.IsZero() || p.alert.TS.Before(lo) {
			lo = p.alert.TS
		}
		if p.alert.TS.After(hi) {
			hi = p.alert.TS
		}
		if len(batch) >= writeBatch || time.Since(lastFlush) > flushEvery {
			lastFlush = time.Now()
			return flush()
		}
		return nil
	})
	if ferr := flush(); err == nil {
		err = ferr
	}
	if !lo.IsZero() {
		_ = a.Store.ExtendDatasetWindow(ctx, datasetID, lo, hi.Add(time.Second))
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	if err == nil {
		_, err = a.audit(ctx, a.Store, actor, "ingest.batch", datasetID, map[string]any{"kind": "alerts", "accepted": rep.Accepted, "rejected": rep.Rejected, "duplicates": rep.Duplicates})
	}
	if err == nil && rep.Accepted > 0 {
		a.notify("dataset.updated", map[string]any{"dataset_id": datasetID})
	}
	return rep, err
}

// IngestAuthEvents streams NDJSON authentication events and runs the five
// detectors over them in order. The detector is seeded with the previous hour
// of the dataset so a spray that straddles two uploads is still seen; the
// seven-day off-hours baseline is not reseeded (documented limitation).
func (a *App) IngestAuthEvents(ctx context.Context, datasetID, actor string, body io.Reader) (IngestReport, error) {
	start := time.Now()
	rep := IngestReport{Errors: []IngestError{}}
	d, err := a.ingestTarget(ctx, datasetID)
	if err != nil {
		return rep, err
	}
	det := detect.New(datasetID)
	seeded := false
	var events []domain.AuthEvent
	var raised []domain.Alert
	var lo, hi time.Time
	flush := func() error {
		if len(events) > 0 {
			ins, dup, err := a.Store.InsertAuthEvents(ctx, events)
			if err != nil {
				return err
			}
			rep.Accepted += ins
			rep.Duplicates += dup
			if err := a.Store.AddDatasetCounts(ctx, datasetID, ins, 0, 0); err != nil {
				return err
			}
			events = events[:0]
		}
		if len(raised) > 0 {
			ins, _, err := a.Store.InsertAlerts(ctx, raised)
			if err != nil {
				return err
			}
			rep.AlertsRaised += ins
			if err := a.Store.AddDatasetCounts(ctx, datasetID, 0, ins, ins); err != nil {
				return err
			}
			raised = raised[:0]
		}
		return nil
	}
	lastFlush := time.Now()
	err = pipeline(ctx, body, func(n int, b []byte) parsed { return ParseAuthEvent(datasetID, n, b) }, func(p parsed) error {
		rep.Received++
		if p.err != nil {
			rep.fail(*p.err)
			return nil
		}
		ev := *p.event
		if !seeded {
			seeded = true
			prior, err := a.Store.AuthEventsBetween(ctx, datasetID, ev.TS.Add(-time.Hour), ev.TS)
			if err != nil {
				return err
			}
			for _, pe := range prior {
				det.Feed(pe) // alerts from these were raised by the earlier upload
			}
		}
		if det.Late(ev) {
			rep.LateEvents++
		}
		raised = append(raised, det.Feed(ev)...)
		events = append(events, ev)
		if lo.IsZero() || ev.TS.Before(lo) {
			lo = ev.TS
		}
		if ev.TS.After(hi) {
			hi = ev.TS
		}
		if len(events) >= writeBatch || time.Since(lastFlush) > flushEvery {
			lastFlush = time.Now()
			return flush()
		}
		return nil
	})
	if ferr := flush(); err == nil {
		err = ferr
	}
	if !lo.IsZero() {
		_ = a.Store.ExtendDatasetWindow(ctx, d.DatasetID, lo, hi.Add(time.Second))
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	if err == nil {
		_, err = a.audit(ctx, a.Store, actor, "ingest.batch", datasetID, map[string]any{"kind": "auth_events", "accepted": rep.Accepted, "rejected": rep.Rejected, "alerts_raised": rep.AlertsRaised})
	}
	if err == nil && rep.AlertsRaised > 0 {
		a.notify("dataset.updated", map[string]any{"dataset_id": datasetID})
	}
	return rep, err
}

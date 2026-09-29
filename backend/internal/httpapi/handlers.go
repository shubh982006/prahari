package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"prahari/internal/app"
	"prahari/internal/core/entity"
	"prahari/internal/core/evaluate"
	"prahari/internal/core/simulate"
	"prahari/internal/domain"
)

// ---------- auth & meta ----------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.Username == "" || len(in.Username) > 64 || in.Password == "" || len(in.Password) > 128 {
		writeError(w, r, validation("body", "username and password are required"))
		return
	}
	tok, u, err := s.app.Login(r.Context(), in.Username, in.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": int(app.TokenLifetime.Seconds()), "user": u})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, err := s.app.Store.UserByID(r.Context(), userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, domain.E(401, "UNAUTHENTICATED", "user no longer exists"))
		return
	}
	writeJSON(w, 200, u)
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	eng := s.app.Engine.Canonical()
	delete(eng, "cuts")
	writeJSON(w, 200, map[string]any{
		"version": s.app.Version, "commit": s.app.Commit, "dialect": s.app.Store.Dialect(),
		"attack_version": s.app.Attack.Version, "llm_enabled": s.app.LLMEnabled, "demo_mode": s.app.DemoMode, "engine": eng,
	})
}

// ---------- datasets ----------

func (s *Server) createSimulation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seed       *int64     `json:"seed"`
		Start      *time.Time `json:"start"`
		Hours      *int       `json:"hours"`
		Scenarios  []string   `json:"scenarios"`
		NoiseLevel string     `json:"noise_level"`
		Users      *int       `json:"users"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	var fe []domain.FieldError
	if in.Seed == nil {
		fe = append(fe, domain.FieldError{Field: "body.seed", Message: "is required"})
	}
	p := simulate.Params{NoiseLevel: in.NoiseLevel, Scenarios: in.Scenarios}
	if in.Seed != nil {
		p.Seed = *in.Seed
	}
	if in.Start != nil {
		p.Start = *in.Start
	}
	if in.Hours != nil {
		if *in.Hours < 1 || *in.Hours > 168 {
			fe = append(fe, domain.FieldError{Field: "body.hours", Message: "must be from 1 to 168"})
		}
		p.Hours = *in.Hours
	}
	if in.Users != nil {
		if *in.Users < 10 || *in.Users > 5000 {
			fe = append(fe, domain.FieldError{Field: "body.users", Message: "must be from 10 to 5000"})
		}
		p.Users = *in.Users
	}
	if in.NoiseLevel != "" && oneOf("", in.NoiseLevel, "low", "normal", "high") != nil {
		fe = append(fe, domain.FieldError{Field: "body.noise_level", Message: "must be one of: low, normal, high"})
	}
	for _, sc := range in.Scenarios {
		if len(sc) != 1 || sc[0] < 'A' || sc[0] > 'F' {
			fe = append(fe, domain.FieldError{Field: "body.scenarios", Message: "each must be one of A–F"})
			break
		}
	}
	if len(fe) > 0 {
		writeError(w, r, domain.Validation(fe...))
		return
	}
	d, err := s.app.Simulate(r.Context(), p, userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/datasets/"+d.DatasetID)
	writeJSON(w, 201, app.ViewDataset(d))
}

func (s *Server) listDatasets(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" {
		if err := oneOf("query.kind", kind, "simulated", "ingested", "adversarial"); err != nil {
			writeError(w, r, err)
			return
		}
	}
	after, afterID, err := s.keyset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	ds, err := s.app.Store.ListDatasets(r.Context(), kind, limit+1, after, afterID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var next *string
	if len(ds) > limit {
		ds = ds[:limit]
		c := s.app.EncodeCursor(keysetCursor{ds[limit-1].CreatedAt, ds[limit-1].DatasetID})
		next = &c
	}
	out := make([]app.DatasetView, len(ds))
	for i, d := range ds {
		out[i] = app.ViewDataset(d)
	}
	writeJSON(w, 200, paged(out, limit, next))
}

func (s *Server) createDataset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DatasetID   string    `json:"dataset_id"`
		WindowStart time.Time `json:"window_start"`
		WindowEnd   time.Time `json:"window_end"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	d, err := s.app.CreateDataset(r.Context(), in.DatasetID, in.WindowStart, in.WindowEnd, userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/datasets/"+d.DatasetID)
	writeJSON(w, 201, app.ViewDataset(d))
}

func (s *Server) getDataset(w http.ResponseWriter, r *http.Request) {
	d, err := s.app.Store.GetDataset(r.Context(), r.PathValue("datasetId"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, app.ViewDataset(d))
}

const maxNDJSONBody = 50 << 20

func (s *Server) ndjson(w http.ResponseWriter, r *http.Request, ingest func(body *http.Request) (app.IngestReport, error)) {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
		writeError(w, r, domain.E(415, "UNSUPPORTED_MEDIA_TYPE", "send Content-Type: application/x-ndjson, one JSON object per line"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxNDJSONBody)
	rep, err := ingest(r)
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeError(w, r, domain.E(413, "PAYLOAD_TOO_LARGE", "bodies are limited to 50 MB; split the file (lines already read were ingested)"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) ingestAuthEvents(w http.ResponseWriter, r *http.Request) {
	s.ndjson(w, r, func(req *http.Request) (app.IngestReport, error) {
		return s.app.IngestAuthEvents(req.Context(), req.PathValue("datasetId"), userOf(req.Context()).UserID, req.Body)
	})
}

func (s *Server) ingestAlerts(w http.ResponseWriter, r *http.Request) {
	s.ndjson(w, r, func(req *http.Request) (app.IngestReport, error) {
		return s.app.IngestAlerts(req.Context(), req.PathValue("datasetId"), userOf(req.Context()).UserID, req.Body)
	})
}

// ---------- alerts ----------

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	ds, err := requireDataset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	from, err := timeParam(r, "from")
	if err != nil {
		writeError(w, r, err)
		return
	}
	to, err := timeParam(r, "to")
	if err != nil {
		writeError(w, r, err)
		return
	}
	sort := r.URL.Query().Get("sort")
	if sort != "" {
		if err := oneOf("query.sort", sort, "ts", "-ts"); err != nil {
			writeError(w, r, err)
			return
		}
	}
	q := app.AlertQuery{DatasetID: ds, From: from, To: to, Sources: csv(r, "source"), Severity: csv(r, "severity"),
		RuleID: r.URL.Query().Get("rule_id"), Entity: r.URL.Query().Get("entity"), Q: r.URL.Query().Get("q"),
		Desc: sort == "-ts", Limit: limit, Cursor: r.URL.Query().Get("cursor")}
	data, next, err := s.app.ListAlerts(r.Context(), q)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, paged(data, limit, next))
}

func (s *Server) alertStats(w http.ResponseWriter, r *http.Request) {
	ds, err := requireDataset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if _, err := s.app.Store.GetDataset(r.Context(), ds); err != nil {
		writeError(w, r, err)
		return
	}
	st, err := s.app.Store.AlertStats(r.Context(), ds)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	ds, err := requireDataset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	al, err := s.app.Store.GetAlert(r.Context(), ds, r.PathValue("alertId"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	v := s.app.AlertView(al)
	if len(v.Raw) == 0 {
		v.Raw = json.RawMessage("{}")
	}
	writeJSON(w, 200, struct {
		app.AlertView
		Raw        json.RawMessage `json:"raw"`
		EntityKeys []string        `json:"entity_keys"`
	}{v, v.Raw, entity.Keys(al.Entities)})
}

// ---------- runs ----------

type runView struct {
	app.Run
	IsCurrent bool            `json:"is_current"`
	Summary   json.RawMessage `json:"summary"`
	Params    json.RawMessage `json:"params"`
	EventsURL string          `json:"events_url"`
}

func (s *Server) viewRun(r *http.Request, run app.Run) runView {
	v := runView{Run: run, Summary: run.Summary, Params: run.Params, EventsURL: "/api/v1/runs/" + run.RunID + "/events"}
	if len(v.Summary) == 0 {
		v.Summary = json.RawMessage("null")
	}
	if len(v.Params) == 0 {
		v.Params = json.RawMessage("{}")
	}
	if d, err := s.app.Store.GetDataset(r.Context(), run.DatasetID); err == nil && d.CurrentRunID != nil {
		v.IsCurrent = *d.CurrentRunID == run.RunID
	}
	return v
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	after, afterID, err := s.keyset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	runs, err := s.app.Store.ListRuns(r.Context(), r.URL.Query().Get("dataset_id"), limit+1, after, afterID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var next *string
	if len(runs) > limit {
		runs = runs[:limit]
		c := s.app.EncodeCursor(keysetCursor{runs[limit-1].CreatedAt, runs[limit-1].RunID})
		next = &c
	}
	out := make([]runView, len(runs))
	for i, run := range runs {
		out[i] = s.viewRun(r, run)
	}
	writeJSON(w, 200, paged(out, limit, next))
}

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DatasetID string         `json:"dataset_id"`
		Overrides *app.Overrides `json:"overrides"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if !app.ValidDatasetID(in.DatasetID) {
		writeError(w, r, validation("body.dataset_id", "is required and must match ^ds_[a-z0-9_]{3,60}$"))
		return
	}
	run, err := s.app.StartRun(r.Context(), in.DatasetID, userOf(r.Context()).UserID, in.Overrides)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/runs/"+run.RunID)
	writeJSON(w, 202, s.viewRun(r, run))
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.app.Store.GetRun(r.Context(), r.PathValue("runId"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, s.viewRun(r, run))
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.app.CancelRun(r.Context(), r.PathValue("runId"), userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 202, s.viewRun(r, run))
}

func (s *Server) receipt(w http.ResponseWriter, r *http.Request) {
	rc, err := s.app.GetReceipt(r.Context(), r.PathValue("runId"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, rc)
}

// ---------- incidents ----------

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	ds, err := requireDataset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	q := r.URL.Query()
	sort := q.Get("sort")
	if sort == "" {
		sort = "-risk"
	}
	if err := oneOf("query.sort", sort, "-risk", "risk", "-first_seen", "first_seen"); err != nil {
		writeError(w, r, err)
		return
	}
	f := app.IncidentFilter{DatasetID: ds, RunID: q.Get("run_id"), Priority: csv(r, "priority"), Label: csv(r, "label"),
		Status: csv(r, "status"), Cohesion: csv(r, "cohesion"), Asset: q.Get("asset"), Assignee: q.Get("assignee"),
		Sort: sort, Limit: limit, Cursor: q.Get("cursor")}
	if b := q.Get("breach"); b != "" {
		v, err := strconv.ParseBool(b)
		if err != nil {
			writeError(w, r, validation("query.breach", "must be true or false"))
			return
		}
		f.Breach = &v
	}
	list, err := s.app.ListIncidents(r.Context(), f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", list.ETag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == list.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, 200, map[string]any{"run_id": list.RunID, "totals": list.Totals, "thresholds": list.Thresholds,
		"data": list.Data, "page": page{Limit: limit, NextCursor: list.NextCursor}})
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.IncidentDetail(r.Context(), r.PathValue("incidentId"), r.URL.Query().Get("run_id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", v.ETag)
	if m := r.Header.Get("If-None-Match"); m != "" && m == v.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) patchIncident(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if err := decode(w, r, &raw); err != nil {
		writeError(w, r, err)
		return
	}
	var p app.IncidentPatch
	for k, v := range raw {
		switch k {
		case "status":
			var st string
			if json.Unmarshal(v, &st) != nil || oneOf("", st, "open", "investigating", "confirmed", "false_positive", "closed") != nil {
				writeError(w, r, validation("body.status", "must be one of: open, investigating, confirmed, false_positive, closed"))
				return
			}
			p.Status = &st
		case "assignee":
			var a *string
			if json.Unmarshal(v, &a) != nil {
				writeError(w, r, validation("body.assignee", "must be a string or null"))
				return
			}
			p.Assignee, p.AssigneeSet = a, true
		default:
			writeError(w, r, validation("body."+k, "unknown field"))
			return
		}
	}
	if p.Status == nil && !p.AssigneeSet {
		writeError(w, r, validation("body", "send status and/or assignee"))
		return
	}
	v, err := s.app.PatchIncident(r.Context(), r.PathValue("incidentId"), r.URL.Query().Get("run_id"), r.Header.Get("If-Match"), userOf(r.Context()).UserID, p)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", v.ETag)
	writeJSON(w, 200, v)
}

type listCursor struct {
	R string `json:"r"`
	I string `json:"i"`
}

func (s *Server) incidentAlerts(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	onChain := r.URL.Query().Get("on_chain") == "true"
	id := r.PathValue("incidentId")
	all, err := s.app.IncidentAlerts(r.Context(), id, r.URL.Query().Get("run_id"), onChain)
	if err != nil {
		writeError(w, r, err)
		return
	}
	start := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		var lc listCursor
		if err := s.app.DecodeCursor(c, &lc); err != nil || lc.R != id {
			writeError(w, r, domain.E(400, "INVALID_CURSOR", "cursor does not belong to this incident"))
			return
		}
		start = len(all)
		for i, a := range all {
			if a.ID == lc.I {
				start = i + 1
			}
		}
	}
	end := min(start+limit, len(all))
	var next *string
	if end < len(all) {
		c := s.app.EncodeCursor(listCursor{id, all[end-1].ID})
		next = &c
	}
	writeJSON(w, 200, paged(all[start:end], limit, next))
}

func (s *Server) incidentGraph(w http.ResponseWriter, r *http.Request) {
	row, err := s.app.GetIncident(r.Context(), r.PathValue("incidentId"), r.URL.Query().Get("run_id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	g := row.Incident.Graph
	assets, _ := s.app.Store.AssetMap(r.Context())
	for i, n := range g.Nodes {
		if n.Type == "host" {
			if a, ok := assets[entity.Value(n.ID)]; ok {
				c := a.Criticality
				g.Nodes[i].Criticality = &c
				g.Nodes[i].DataClasses = a.DataClasses
			}
		}
	}
	writeJSON(w, 200, g)
}

func (s *Server) incidentTimeline(w http.ResponseWriter, r *http.Request) {
	row, err := s.app.GetIncident(r.Context(), r.PathValue("incidentId"), r.URL.Query().Get("run_id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, row.Incident.Timeline)
}

func (s *Server) narrativeFor(w http.ResponseWriter, r *http.Request, regenerate bool) {
	id := r.PathValue("incidentId")
	row, err := s.app.GetIncident(r.Context(), id, r.URL.Query().Get("run_id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	v, err := s.app.Narrative(r.Context(), row.RunID, id, regenerate)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) narrative(w http.ResponseWriter, r *http.Request) { s.narrativeFor(w, r, false) }
func (s *Server) regenerateNarrative(w http.ResponseWriter, r *http.Request) {
	s.narrativeFor(w, r, true)
}

func (s *Server) cohesion(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.Cohesion(r.Context(), r.PathValue("incidentId"), r.URL.Query().Get("run_id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) split(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Bridge *struct {
			AlertA string `json:"alert_a"`
			AlertB string `json:"alert_b"`
		} `json:"bridge"`
		Note string `json:"note"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.Bridge == nil || in.Bridge.AlertA == "" || in.Bridge.AlertB == "" {
		writeError(w, r, validation("body.bridge", "alert_a and alert_b are required"))
		return
	}
	if len(in.Note) > 2000 {
		writeError(w, r, validation("body.note", "at most 2000 characters"))
		return
	}
	res, err := s.app.SplitIncident(r.Context(), r.PathValue("incidentId"), in.Bridge.AlertA, in.Bridge.AlertB, in.Note, userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 201, res)
}

func (s *Server) counterfactuals(w http.ResponseWriter, r *http.Request) {
	whatIf, err := app.ParseWhatIf(r.URL.Query()["what_if_criticality"])
	if err != nil {
		writeError(w, r, err)
		return
	}
	set, err := s.app.Counterfactuals(r.Context(), r.PathValue("incidentId"), r.URL.Query().Get("run_id"), whatIf)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, set)
}

func (s *Server) listFeedback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("incidentId")
	if _, err := s.app.GetIncident(r.Context(), id, ""); err != nil {
		writeError(w, r, err)
		return
	}
	fs, err := s.app.Store.ListFeedback(r.Context(), id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if fs == nil {
		fs = []app.Feedback{}
	}
	writeJSON(w, 200, map[string]any{"data": fs})
}

func (s *Server) createFeedback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Verdict  string  `json:"verdict"`
		Note     *string `json:"note"`
		RunID    string  `json:"run_id"`
		Suppress *struct {
			RuleID    string     `json:"rule_id"`
			EntityKey string     `json:"entity_key"`
			ExpiresAt *time.Time `json:"expires_at"`
		} `json:"suppress"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if err := oneOf("body.verdict", in.Verdict, "confirmed", "false_positive"); err != nil {
		writeError(w, r, err)
		return
	}
	if in.Note != nil && len(*in.Note) > 2000 {
		writeError(w, r, validation("body.note", "at most 2000 characters"))
		return
	}
	fi := app.FeedbackInput{Verdict: in.Verdict, Note: in.Note, RunID: in.RunID}
	if in.Suppress != nil {
		if in.Suppress.RuleID == "" || entity.Type(in.Suppress.EntityKey) == "" || entity.Value(in.Suppress.EntityKey) == "" {
			writeError(w, r, validation("body.suppress", "rule_id and an entity_key like host:dc01 are required"))
			return
		}
		fi.Suppress = &app.SuppressInput{RuleID: in.Suppress.RuleID, EntityKey: strings.ToLower(in.Suppress.EntityKey), ExpiresAt: in.Suppress.ExpiresAt}
	}
	u := userOf(r.Context())
	res, err := s.app.RecordFeedback(r.Context(), r.PathValue("incidentId"), u.UserID, u.Role, fi)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 201, res)
}

// ---------- rules & assets ----------

func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	rs, err := s.app.Rules(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"data": rs})
}

func (s *Server) suppressions(w http.ResponseWriter, r *http.Request) {
	ss, err := s.app.Store.ListSuppressions(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if ss == nil {
		ss = []domain.Suppression{}
	}
	writeJSON(w, 200, map[string]any{"data": ss})
}

func (s *Server) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("suppressionId"), 10, 64)
	if err != nil {
		writeError(w, r, domain.NotFound("suppression"))
		return
	}
	if err := s.app.DeleteSuppression(r.Context(), id, userOf(r.Context()).UserID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	minCrit := 0
	if v := r.URL.Query().Get("min_criticality"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10 {
			writeError(w, r, validation("query.min_criticality", "must be from 1 to 10"))
			return
		}
		minCrit = n
	}
	dc := r.URL.Query().Get("data_class")
	if dc != "" {
		if err := oneOf("query.data_class", dc, "pii", "financial", "credentials", "source_code"); err != nil {
			writeError(w, r, err)
			return
		}
	}
	as, err := s.app.Store.ListAssets(r.Context(), minCrit, dc)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if as == nil {
		as = []domain.Asset{}
	}
	writeJSON(w, 200, map[string]any{"data": as})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	a, err := s.app.Store.GetAsset(r.Context(), r.PathValue("hostname"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) putAsset(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("hostname")
	if host != entity.NormHost(host) || len(host) > 63 || host == "" {
		writeError(w, r, validation("path.hostname", "must be the normalised short name: lowercase, no domain suffix"))
		return
	}
	var in struct {
		Role        string   `json:"role"`
		Criticality int      `json:"criticality"`
		DataClasses []string `json:"data_classes"`
		Owner       string   `json:"owner"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	var fe []domain.FieldError
	if in.Role == "" {
		fe = append(fe, domain.FieldError{Field: "body.role", Message: "is required"})
	}
	if in.Criticality < 1 || in.Criticality > 10 {
		fe = append(fe, domain.FieldError{Field: "body.criticality", Message: "must be from 1 to 10"})
	}
	seen := map[string]bool{}
	for _, c := range in.DataClasses {
		if oneOf("", c, "pii", "financial", "credentials", "source_code") != nil || seen[c] {
			fe = append(fe, domain.FieldError{Field: "body.data_classes", Message: "unique values from: pii, financial, credentials, source_code"})
			break
		}
		seen[c] = true
	}
	if len(fe) > 0 {
		writeError(w, r, domain.Validation(fe...))
		return
	}
	a := domain.Asset{Hostname: host, Role: in.Role, Criticality: in.Criticality, DataClasses: in.DataClasses, Owner: in.Owner, UpdatedAt: time.Now().UTC()}
	if a.DataClasses == nil {
		a.DataClasses = []string{}
	}
	var created bool
	err := s.app.Store.InTx(r.Context(), func(tx app.Store) error {
		var err error
		if created, err = tx.UpsertAsset(r.Context(), a); err != nil {
			return err
		}
		return s.app.Audit(r.Context(), tx, userOf(r.Context()).UserID, "asset.upserted", host, a)
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, a)
}

// ---------- adversary ----------

func (s *Server) createCampaign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BaseDataset string    `json:"base_dataset"`
		Strategy    string    `json:"strategy"`
		Budgets     []float64 `json:"budgets"`
		Mitigated   bool      `json:"mitigated"`
		Seed        *int64    `json:"seed"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if !app.ValidDatasetID(in.BaseDataset) {
		writeError(w, r, validation("body.base_dataset", "is required and must match ^ds_[a-z0-9_]{3,60}$"))
		return
	}
	seed := int64(42)
	if in.Seed != nil {
		seed = *in.Seed
	}
	c, err := s.app.CreateCampaign(r.Context(), app.CampaignInput{BaseDataset: in.BaseDataset, Strategy: in.Strategy,
		Budgets: in.Budgets, Mitigated: in.Mitigated, Seed: seed}, userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/adversary/campaigns/"+c.CampaignID)
	writeJSON(w, 202, c)
}

func (s *Server) listCampaigns(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	after, afterID, err := s.keyset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	cs, err := s.app.Store.ListCampaigns(r.Context(), r.URL.Query().Get("base_dataset"), limit+1, after, afterID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var next *string
	if len(cs) > limit {
		cs = cs[:limit]
		c := s.app.EncodeCursor(keysetCursor{cs[limit-1].CreatedAt, cs[limit-1].CampaignID})
		next = &c
	}
	out := make([]app.CampaignView, 0, len(cs))
	for _, c := range cs {
		v, _ := s.app.GetCampaign(r.Context(), c.CampaignID)
		out = append(out, v.CampaignView)
	}
	writeJSON(w, 200, paged(out, limit, next))
}

func (s *Server) getCampaign(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.GetCampaign(r.Context(), r.PathValue("campaignId"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) curve(w http.ResponseWriter, r *http.Request) {
	base := r.URL.Query().Get("base_dataset")
	if !app.ValidDatasetID(base) {
		writeError(w, r, validation("query.base_dataset", "is required and must match ^ds_[a-z0-9_]{3,60}$"))
		return
	}
	metric := r.URL.Query().Get("metric")
	if metric != "" {
		if err := oneOf("query.metric", metric, "scenario_recall", "pairwise_recall", "pairwise_precision"); err != nil {
			writeError(w, r, err)
			return
		}
	}
	floor := 0.7
	if v := r.URL.Query().Get("floor"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 1 {
			writeError(w, r, validation("query.floor", "must be a number from 0 to 1"))
			return
		}
		floor = f
	}
	c, err := s.app.EvasionCurve(r.Context(), base, metric, floor)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, c)
}

// ---------- compliance ----------

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "open"
	}
	if err := oneOf("query.state", state, "open", "overdue", "closed", "all"); err != nil {
		writeError(w, r, err)
		return
	}
	cs, now, err := s.app.ListCases(r.Context(), r.URL.Query().Get("dataset_id"), state)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"server_time": now.Format(time.RFC3339), "data": cs})
}

func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	c, now, err := s.app.GetCase(r.Context(), r.PathValue("caseId"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, struct {
		app.CaseDetailView
		ServerTime string `json:"server_time"`
	}{c, now.Format(time.RFC3339)})
}

func (s *Server) draft(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if err := oneOf("query.format", format, "json", "markdown"); err != nil {
		writeError(w, r, err)
		return
	}
	d, md, err := s.app.Draft(r.Context(), r.PathValue("caseId"), r.PathValue("track"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if format == "markdown" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte(md))
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) submission(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SubmittedAt *time.Time `json:"submitted_at"`
		Reference   string     `json:"reference"`
		Note        string     `json:"note"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	var fe []domain.FieldError
	if in.SubmittedAt == nil {
		fe = append(fe, domain.FieldError{Field: "body.submitted_at", Message: "is required"})
	}
	if in.Reference == "" || len(in.Reference) > 128 {
		fe = append(fe, domain.FieldError{Field: "body.reference", Message: "is required, at most 128 characters"})
	}
	if len(in.Note) > 2000 {
		fe = append(fe, domain.FieldError{Field: "body.note", Message: "at most 2000 characters"})
	}
	if len(fe) > 0 {
		writeError(w, r, domain.Validation(fe...))
		return
	}
	c, err := s.app.RecordSubmission(r.Context(), r.PathValue("caseId"), r.PathValue("track"), userOf(r.Context()).UserID, in.Reference, in.Note, in.SubmittedAt.UTC())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 201, c)
}

func (s *Server) retention(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.Retention(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

// ---------- evaluations & audit ----------

func (s *Server) createEvaluation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunID        string                 `json:"run_id"`
		AnalystModel *evaluate.AnalystModel `json:"analyst_model"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.RunID == "" {
		writeError(w, r, validation("body.run_id", "is required"))
		return
	}
	m := evaluate.DefaultAnalyst
	if in.AnalystModel != nil {
		m = *in.AnalystModel
	}
	v, err := s.app.Evaluate(r.Context(), in.RunID, m, userOf(r.Context()).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 201, v)
}

func (s *Server) latestEvaluation(w http.ResponseWriter, r *http.Request) {
	ds, err := requireDataset(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	body, err := s.app.LatestEvaluation(r.Context(), ds)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var before int64
	if c := r.URL.Query().Get("cursor"); c != "" {
		var k struct {
			S int64 `json:"s"`
		}
		if err := s.app.DecodeCursor(c, &k); err != nil {
			writeError(w, r, err)
			return
		}
		before = k.S
	}
	es, err := s.app.Store.ListAudit(r.Context(), r.URL.Query().Get("subject"), r.URL.Query().Get("action"), limit+1, before)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var next *string
	if len(es) > limit {
		es = es[:limit]
		c := s.app.EncodeCursor(struct {
			S int64 `json:"s"`
		}{es[limit-1].Seq})
		next = &c
	}
	if es == nil {
		es = []app.AuditEntry{}
	}
	writeJSON(w, 200, paged(es, limit, next))
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	v, err := s.app.VerifyAudit(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

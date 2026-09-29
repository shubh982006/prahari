package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"prahari/internal/app"
	"prahari/internal/config"
	"prahari/internal/domain"
)

// Readiness reports whether the process can serve: DB reachable, migrations
// current, ATT&CK loaded.
type Readiness func(ctx context.Context) (ok bool, failing string)

type Server struct {
	app     *app.App
	cfg     config.Config
	log     *slog.Logger
	limiter *limiter
	metrics *metrics
	ready   Readiness
}

func New(a *app.App, cfg config.Config, log *slog.Logger, ready Readiness) *Server {
	s := &Server{app: a, cfg: cfg, log: log, limiter: newLimiter(), metrics: newMetrics(), ready: ready}
	s.metrics.gauges = func() map[string]float64 {
		return map[string]float64{"prahari_sse_subscribers": float64(a.Pub.Subscribers())}
	}
	return s
}

// Handler returns the full router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	anyone := route{}
	lead := route{lead: true}
	sse := route{sse: true}
	api := func(pattern string, rt route, h http.HandlerFunc) {
		method, path, _ := strings.Cut(pattern, " ")
		mux.HandleFunc(method+" /api/v1"+path, s.guard(rt, h))
	}

	api("POST /auth/login", route{public: true, limit: "login"}, s.login)
	api("GET /auth/me", anyone, s.me)
	api("GET /meta", anyone, s.meta)

	api("POST /simulations", lead, s.createSimulation)
	api("GET /datasets", anyone, s.listDatasets)
	api("POST /datasets", lead, s.createDataset)
	api("GET /datasets/{datasetId}", anyone, s.getDataset)
	api("POST /datasets/{datasetId}/auth-events", lead, s.ingestAuthEvents)
	api("POST /datasets/{datasetId}/alerts", lead, s.ingestAlerts)

	api("GET /alerts", anyone, s.listAlerts)
	api("GET /alerts/stats", anyone, s.alertStats)
	api("GET /alerts/{alertId}", anyone, s.getAlert)

	api("GET /runs", anyone, s.listRuns)
	api("POST /runs", lead, s.idempotent(s.createRun))
	api("GET /runs/{runId}", anyone, s.getRun)
	api("POST /runs/{runId}/cancel", lead, s.cancelRun)
	api("GET /runs/{runId}/events", sse, s.runEvents)
	api("GET /runs/{runId}/receipt", anyone, s.receipt)
	api("GET /events", sse, s.globalEvents)

	api("GET /incidents", anyone, s.listIncidents)
	api("GET /incidents/{incidentId}", anyone, s.getIncident)
	api("PATCH /incidents/{incidentId}", anyone, s.patchIncident)
	api("GET /incidents/{incidentId}/alerts", anyone, s.incidentAlerts)
	api("GET /incidents/{incidentId}/graph", anyone, s.incidentGraph)
	api("GET /incidents/{incidentId}/timeline", anyone, s.incidentTimeline)
	api("GET /incidents/{incidentId}/narrative", anyone, s.narrative)
	api("POST /incidents/{incidentId}/narrative/regenerate", route{limit: "narrative"}, s.regenerateNarrative)
	api("GET /incidents/{incidentId}/cohesion", anyone, s.cohesion)
	api("POST /incidents/{incidentId}/split", lead, s.split)
	api("GET /incidents/{incidentId}/counterfactuals", anyone, s.counterfactuals)
	api("GET /incidents/{incidentId}/feedback", anyone, s.listFeedback)
	api("POST /incidents/{incidentId}/feedback", anyone, s.idempotent(s.createFeedback))

	api("GET /rules", anyone, s.rules)
	api("GET /suppressions", anyone, s.suppressions)
	api("DELETE /suppressions/{suppressionId}", lead, s.deleteSuppression)

	api("GET /assets", anyone, s.listAssets)
	api("GET /assets/{hostname}", anyone, s.getAsset)
	api("PUT /assets/{hostname}", lead, s.putAsset)

	api("POST /adversary/campaigns", route{lead: true, limit: "campaign"}, s.idempotent(s.createCampaign))
	api("GET /adversary/campaigns", anyone, s.listCampaigns)
	api("GET /adversary/campaigns/{campaignId}", anyone, s.getCampaign)
	api("GET /adversary/campaigns/{campaignId}/events", sse, s.campaignEvents)
	api("GET /adversary/curve", anyone, s.curve)

	api("GET /compliance/cases", anyone, s.listCases)
	api("GET /compliance/cases/{caseId}", anyone, s.getCase)
	api("GET /compliance/cases/{caseId}/drafts/{track}", anyone, s.draft)
	api("POST /compliance/cases/{caseId}/tracks/{track}/submission", lead, s.submission)
	api("GET /governance/retention", anyone, s.retention)

	api("POST /evaluations", lead, s.createEvaluation)
	api("GET /evaluations/latest", anyone, s.latestEvaluation)

	api("GET /audit", anyone, s.listAudit)
	api("GET /audit/verify", anyone, s.verifyAudit)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", s.metrics.handler)
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, domain.NotFound("route "+r.Method+" "+r.URL.Path))
	})
	return s.base(s.cors(mux))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if ok, failing := s.ready(ctx); !ok {
		writeJSON(w, 503, map[string]string{"status": "unavailable", "failing": failing})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

// ---------- query helpers ----------

type page struct {
	Limit      int     `json:"limit"`
	NextCursor *string `json:"next_cursor"`
}

func paged(data any, limit int, next *string) map[string]any {
	return map[string]any{"data": data, "page": page{Limit: limit, NextCursor: next}}
}

func limitParam(r *http.Request) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 500 {
		return 0, validation("query.limit", "must be an integer from 1 to 500")
	}
	return n, nil
}

func csv(r *http.Request, name string) []string {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func timeParam(r *http.Request, name string) (*time.Time, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, validation("query."+name, "must be an RFC 3339 date-time")
	}
	return &t, nil
}

func requireDataset(r *http.Request) (string, error) {
	ds := r.URL.Query().Get("dataset_id")
	if ds == "" {
		return "", validation("query.dataset_id", "is required")
	}
	if !app.ValidDatasetID(ds) {
		return "", validation("query.dataset_id", "must match ^ds_[a-z0-9_]{3,60}$")
	}
	return ds, nil
}

func oneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return validation(field, "must be one of: "+strings.Join(allowed, ", "))
}

// keysetCursor is the (created_at, id) position for newest-first lists.
type keysetCursor struct {
	T time.Time `json:"t"`
	I string    `json:"i"`
}

func (s *Server) keyset(r *http.Request) (*time.Time, string, error) {
	c := r.URL.Query().Get("cursor")
	if c == "" {
		return nil, "", nil
	}
	var k keysetCursor
	if err := s.app.DecodeCursor(c, &k); err != nil {
		return nil, "", err
	}
	return &k.T, k.I, nil
}

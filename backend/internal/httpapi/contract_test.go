package httpapi_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"prahari/internal/adapters/broker/inproc"
	"prahari/internal/adapters/clock"
	"prahari/internal/adapters/llm/azureopenai"
	"prahari/internal/adapters/store/sqlstore"
	"prahari/internal/app"
	"prahari/internal/config"
	"prahari/internal/core/attack"
	"prahari/internal/core/correlate"
	"prahari/internal/httpapi"
)

const specURL = "https://prahari.dev/openapi.json"

// spec loads openapi.yaml as a JSON Schema resource so any response can be
// validated against the schema its path, method and status declare.
type spec struct {
	doc      map[string]any
	compiler *jsonschema.Compiler
	cache    map[string]*jsonschema.Schema
}

func loadSpec(t *testing.T) *spec {
	b, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	// yaml gives map[string]any for mappings; round-trip through JSON so the
	// validator sees plain JSON values.
	js, _ := json.Marshal(doc)
	var generic any
	_ = json.Unmarshal(js, &generic)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource(specURL, generic); err != nil {
		t.Fatal(err)
	}
	return &spec{doc: generic.(map[string]any), compiler: c, cache: map[string]*jsonschema.Schema{}}
}

func esc(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }

func (s *spec) pointer(method, template string, status int) (string, error) {
	paths := s.doc["paths"].(map[string]any)
	op, ok := paths[template].(map[string]any)[strings.ToLower(method)].(map[string]any)
	if !ok {
		return "", fmt.Errorf("spec has no %s %s", method, template)
	}
	responses := op["responses"].(map[string]any)
	code := fmt.Sprint(status)
	resp, ok := responses[code].(map[string]any)
	if !ok {
		return "", fmt.Errorf("spec does not declare %d for %s %s", status, method, template)
	}
	base := "#/paths/" + esc(template) + "/" + strings.ToLower(method) + "/responses/" + code
	if ref, ok := resp["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/responses/")
		resp = s.doc["components"].(map[string]any)["responses"].(map[string]any)[name].(map[string]any)
		base = "#/components/responses/" + name
	}
	content, ok := resp["content"].(map[string]any)
	if !ok {
		return "", nil // no body declared (204, 304)
	}
	for _, ct := range []string{"application/json", "application/problem+json"} {
		if _, ok := content[ct]; ok {
			return base + "/content/" + esc(ct) + "/schema", nil
		}
	}
	return "", nil
}

func (s *spec) validate(t *testing.T, method, template string, status int, body []byte) {
	t.Helper()
	ptr, err := s.pointer(method, template, status)
	if err != nil {
		t.Errorf("%v (body %s)", err, trim(body))
		return
	}
	if ptr == "" {
		return
	}
	sch, ok := s.cache[ptr]
	if !ok {
		if sch, err = s.compiler.Compile(specURL + ptr); err != nil {
			t.Fatalf("compile %s: %v", ptr, err)
		}
		s.cache[ptr] = sch
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Errorf("%s %s %d: not JSON: %s", method, template, status, trim(body))
		return
	}
	if err := sch.Validate(v); err != nil {
		t.Errorf("%s %s %d does not match the contract:\n%v\nbody: %s", method, template, status, err, trim(body))
	}
}

func trim(b []byte) string {
	if len(b) > 600 {
		return string(b[:600]) + "…"
	}
	return string(b)
}

type client struct {
	t     *testing.T
	base  string
	spec  *spec
	token string
}

var paramRe = regexp.MustCompile(`\{[^}]+\}`)

// do calls the API and validates the response against the operation the
// template names. It returns status, headers and body.
func (c *client) do(method, template string, params []string, body any, hdr ...string) (int, http.Header, []byte) {
	c.t.Helper()
	path := template
	for _, p := range params {
		path = strings.Replace(path, paramRe.FindString(path), p, 1)
	}
	query := ""
	if i := strings.IndexByte(template, '?'); i >= 0 {
		template, query = template[:i], ""
	}
	_ = query
	var rd io.Reader
	ct := "application/json"
	switch b := body.(type) {
	case nil:
	case string:
		rd, ct = strings.NewReader(b), "application/x-ndjson"
	default:
		js, _ := json.Marshal(b)
		rd = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, c.base+"/api/v1"+path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", ct)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	c.spec.validate(c.t, method, template, res.StatusCode, b)
	return res.StatusCode, res.Header, b
}

func field(b []byte, path ...string) any {
	var v any
	_ = json.Unmarshal(b, &v)
	for _, p := range path {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			var i int
			fmt.Sscan(p, &i)
			if i >= len(x) {
				return nil
			}
			v = x[i]
		default:
			return nil
		}
	}
	return v
}

func str(v any) string { s, _ := v.(string); return s }

var pgSeq atomic.Int64

func stores(t *testing.T) map[string]func(t *testing.T) app.Store {
	out := map[string]func(t *testing.T) app.Store{
		"sqlite": func(t *testing.T) app.Store {
			s, err := sqlstore.Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	}
	if admin := os.Getenv("PRAHARI_TEST_PG"); admin != "" {
		out["postgres"] = func(t *testing.T) app.Store {
			name := fmt.Sprintf("prahari_http_%d_%d", time.Now().UnixNano()%1e9, pgSeq.Add(1))
			adb, _ := sql.Open("pgx", admin)
			if _, err := adb.Exec("CREATE DATABASE " + name); err != nil {
				t.Fatal(err)
			}
			s, err := sqlstore.Open(context.Background(), strings.Replace(admin, "/postgres?", "/"+name+"?", 1))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				s.Close()
				_, _ = adb.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
				adb.Close()
			})
			return s
		}
	}
	return out
}

func TestContract(t *testing.T) {
	sp := loadSpec(t)
	for name, newStore := range stores(t) {
		t.Run(name, func(t *testing.T) { contract(t, sp, newStore(t)) })
	}
}

func contract(t *testing.T, sp *spec, store app.Store) {
	cat, err := attack.LoadFile("../../data/attack/enterprise-attack-19.0.min.json")
	if err != nil {
		t.Fatal(err)
	}
	a := app.New(app.Deps{Store: store, Pub: inproc.New(), LLM: azureopenai.Disabled{}, Clock: clock.System{},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Attack: cat, Engine: correlate.DefaultConfig(),
		DataDir: t.TempDir(), Version: "test", JWTSecret: []byte("0123456789abcdef0123456789abcdef")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Setup(ctx, "lead-pw", "analyst-pw"); err != nil {
		t.Fatal(err)
	}
	a.Start(ctx)
	defer a.Stop(context.Background())
	cfg := config.Defaults()
	srv := httptest.NewServer(httpapi.New(a, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(context.Context) (bool, string) { return true, "" }).Handler())
	defer srv.Close()
	c := &client{t: t, base: srv.URL, spec: sp}

	// auth
	if code, _, _ := c.do("POST", "/auth/login", nil, map[string]string{"username": "meow", "password": "wrong"}); code != 401 {
		t.Fatalf("bad password: %d", code)
	}
	code, _, b := c.do("POST", "/auth/login", nil, map[string]string{"username": "meow", "password": "lead-pw"})
	if code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	c.token = str(field(b, "access_token"))
	if code, _, _ := (&client{t: t, base: srv.URL, spec: sp}).do("GET", "/meta", nil, nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	c.do("GET", "/auth/me", nil, nil)
	c.do("GET", "/meta", nil, nil)

	// datasets and simulation
	code, hdr, b := c.do("POST", "/simulations", nil, map[string]any{"seed": 42})
	if code != 201 || hdr.Get("Location") == "" {
		t.Fatalf("simulate: %d %s", code, b)
	}
	ds := str(field(b, "dataset_id"))
	if code, _, _ := c.do("POST", "/simulations", nil, map[string]any{"seed": 42}); code != 409 {
		t.Fatalf("duplicate simulation: %d", code)
	}
	if code, _, _ := c.do("POST", "/simulations", nil, map[string]any{"seed": 1, "hours": 999}); code != 400 {
		t.Fatalf("validation: %d", code)
	}
	c.do("GET", "/datasets", nil, nil)
	c.do("GET", "/datasets/{datasetId}", []string{ds}, nil)
	if code, _, _ := c.do("GET", "/datasets/{datasetId}", []string{"ds_does_not_exist"}, nil); code != 404 {
		t.Fatal("unknown dataset should be 404")
	}

	// ingest into a fresh dataset: a bad line never fails the batch
	code, _, _ = c.do("POST", "/datasets", nil, map[string]any{"dataset_id": "ds_ext_upload",
		"window_start": "2026-09-29T00:00:00Z", "window_end": "2026-09-30T00:00:00Z"})
	if code != 201 {
		t.Fatalf("create dataset: %d", code)
	}
	nd := `{"id":"X1","timestamp":"2026-09-29T04:35:12Z","source":"edr","rule_id":"EDR-RDP-LATERAL","rule_name":"RDP","severity":"high","technique_id":"T1021.001","entities":{"users":["priya@corp.local"],"hosts":["WS-114","DC01"]},"raw":{"EventID":4624}}
{"id":"X2","timestamp":"not-a-time","source":"edr","rule_id":"R","rule_name":"r","severity":"high","entities":{}}
{"id":"X3","timestamp":"2026-09-29T04:36:12Z","source":"edr","rule_id":"R","rule_name":"r","severity":"high","entities":{},"surprise":1}
`
	code, _, b = c.do("POST", "/datasets/{datasetId}/alerts", []string{"ds_ext_upload"}, nd)
	if code != 200 || field(b, "accepted") != 1.0 || field(b, "rejected") != 2.0 {
		t.Fatalf("ingest report: %d %s", code, b)
	}
	code, _, b = c.do("POST", "/datasets/{datasetId}/auth-events", []string{"ds_ext_upload"},
		`{"event_id":"E1","timestamp":"2026-09-29T03:32:11Z","username":"priya@corp.local","src_ip":"185.220.101.7","geo":"NL-AMS","result":"failure","app":"vpn"}`+"\n")
	if code != 200 || field(b, "accepted") != 1.0 {
		t.Fatalf("auth ingest: %d %s", code, b)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/datasets/ds_ext_upload/alerts", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "text/plain")
	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != 415 {
		t.Fatalf("wrong content type: %d", res.StatusCode)
	}

	// a run, streamed
	code, _, b = c.do("POST", "/runs", nil, map[string]any{"dataset_id": ds}, "Idempotency-Key", "run-key-1")
	if code != 202 {
		t.Fatalf("run: %d %s", code, b)
	}
	runID := str(field(b, "run_id"))
	if code, h, _ := c.do("POST", "/runs", nil, map[string]any{"dataset_id": ds}, "Idempotency-Key", "run-key-1"); code != 202 || h.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("idempotent replay: %d %v", code, h)
	}
	if code, _, _ := c.do("POST", "/runs", nil, map[string]any{"dataset_id": ds, "overrides": map[string]any{"link_window": "1s"}}); code != 400 {
		t.Fatalf("override validation: %d", code)
	}
	sse, err := http.Get(srv.URL + "/api/v1/runs/" + runID + "/events?access_token=" + c.token)
	if err != nil {
		t.Fatal(err)
	}
	stream, _ := io.ReadAll(sse.Body)
	sse.Body.Close()
	if !strings.HasPrefix(sse.Header.Get("Content-Type"), "text/event-stream") || !strings.Contains(string(stream), "event: done") {
		t.Fatalf("run stream did not finish with done:\n%s", stream)
	}
	c.do("GET", "/runs/{runId}", []string{runID}, nil)
	c.do("GET", "/runs", nil, nil)
	c.do("GET", "/runs/{runId}/receipt", []string{runID}, nil)
	if code, _, _ := c.do("POST", "/runs/{runId}/cancel", []string{runID}, nil); code != 409 {
		t.Fatalf("cancel a finished run: %d", code)
	}

	// incidents
	code, h, b := c.do("GET", "/incidents?dataset_id="+ds, nil, nil)
	if code != 200 {
		t.Fatalf("incidents: %d %s", code, b)
	}
	if code, _, _ := c.do("GET", "/incidents?dataset_id="+ds, nil, nil, "If-None-Match", h.Get("ETag")); code != 304 {
		t.Fatalf("If-None-Match: %d", code)
	}
	c.do("GET", "/incidents?dataset_id="+ds+"&priority=P1,P2&cohesion=fragile,moderate&limit=2", nil, nil)
	if code, _, _ := c.do("GET", "/incidents?dataset_id="+ds+"&cursor=forged", nil, nil); code != 400 {
		t.Fatalf("forged cursor: %d", code)
	}
	inc := str(field(b, "data", "0", "incident_id"))
	code, h, b = c.do("GET", "/incidents/{incidentId}", []string{inc}, nil)
	etag := h.Get("ETag")
	for _, p := range []string{"/incidents/{incidentId}/alerts", "/incidents/{incidentId}/graph", "/incidents/{incidentId}/timeline",
		"/incidents/{incidentId}/narrative", "/incidents/{incidentId}/cohesion", "/incidents/{incidentId}/counterfactuals", "/incidents/{incidentId}/feedback"} {
		if code, _, b := c.do("GET", p, []string{inc}, nil); code != 200 {
			t.Errorf("%s: %d %s", p, code, b)
		}
	}
	c.do("GET", "/incidents/{incidentId}/counterfactuals?what_if_criticality=dc01:3", []string{inc}, nil)
	c.do("POST", "/incidents/{incidentId}/narrative/regenerate", []string{inc}, nil)
	if code, _, _ := c.do("PATCH", "/incidents/{incidentId}", []string{inc}, map[string]any{"status": "investigating"}); code != 428 {
		t.Fatal("PATCH without If-Match must be 428")
	}
	if code, _, b := c.do("PATCH", "/incidents/{incidentId}", []string{inc}, map[string]any{"status": "investigating", "assignee": "u_meow"}, "If-Match", etag); code != 200 {
		t.Fatalf("patch: %d %s", code, b)
	}
	if code, _, _ := c.do("PATCH", "/incidents/{incidentId}", []string{inc}, map[string]any{"status": "closed"}, "If-Match", etag); code != 412 {
		t.Fatal("stale ETag must be 412")
	}
	if code, _, b := c.do("POST", "/incidents/{incidentId}/feedback", []string{inc}, map[string]any{"verdict": "confirmed",
		"suppress": map[string]any{"rule_id": "NET-PORTSCAN", "entity_key": "ip:10.1.9.20"}}); code != 201 {
		t.Fatalf("feedback: %d %s", code, b)
	}
	if code, _, _ := c.do("POST", "/incidents/{incidentId}/feedback", []string{inc}, map[string]any{"verdict": "maybe"}); code != 400 {
		t.Fatal("bad verdict must be 400")
	}
	if code, _, _ := c.do("POST", "/incidents/{incidentId}/split", []string{inc}, map[string]any{"bridge": map[string]any{"alert_a": "x", "alert_b": "y"}}); code != 409 {
		t.Fatal("split on a non-bridge must be 409")
	}
	_, _, list := c.do("GET", "/incidents?dataset_id="+ds+"&cohesion=fragile", nil, nil)
	if frag := str(field(list, "data", "0", "incident_id")); frag != "" {
		_, _, cb := c.do("GET", "/incidents/{incidentId}/cohesion", []string{frag}, nil)
		br := map[string]any{"alert_a": field(cb, "bridge_edges", "0", "alert_a"), "alert_b": field(cb, "bridge_edges", "0", "alert_b")}
		if code, _, b := c.do("POST", "/incidents/{incidentId}/split", []string{frag}, map[string]any{"bridge": br, "note": "contract test"}); code != 201 {
			t.Fatalf("split: %d %s", code, b)
		}
	}

	// alerts
	_, _, b = c.do("GET", "/alerts?dataset_id="+ds+"&limit=3&severity=high,critical", nil, nil)
	alertID := str(field(b, "data", "0", "id"))
	next := str(field(b, "page", "next_cursor"))
	c.do("GET", "/alerts?dataset_id="+ds+"&limit=3&severity=high,critical&cursor="+next, nil, nil)
	c.do("GET", "/alerts?dataset_id="+ds+"&entity=host:dc01&sort=-ts", nil, nil)
	c.do("GET", "/alerts/stats?dataset_id="+ds, nil, nil)
	c.do("GET", "/alerts/{alertId}?dataset_id="+ds, []string{alertID}, nil)
	if code, _, _ := c.do("GET", "/alerts", nil, nil); code != 400 {
		t.Fatal("missing dataset_id must be 400")
	}

	// rules and assets
	c.do("GET", "/rules", nil, nil)
	_, _, sups := c.do("GET", "/suppressions", nil, nil)
	if id := field(sups, "data", "0", "suppression_id"); id != nil {
		if code, _, _ := c.do("DELETE", "/suppressions/{suppressionId}", []string{fmt.Sprint(id)}, nil); code != 204 {
			t.Fatal("delete suppression")
		}
	}
	c.do("GET", "/assets?min_criticality=7&data_class=pii", nil, nil)
	c.do("GET", "/assets/{hostname}", []string{"dc01"}, nil)
	if code, _, _ := c.do("PUT", "/assets/{hostname}", []string{"ws-intern-07"}, map[string]any{"role": "intern_laptop", "criticality": 2}); code != 200 {
		t.Fatal("asset update")
	}
	if code, _, _ := c.do("PUT", "/assets/{hostname}", []string{"new-host-1"}, map[string]any{"role": "workstation", "criticality": 3, "data_classes": []string{"pii"}}); code != 201 {
		t.Fatal("asset create")
	}

	// compliance
	_, _, cases := c.do("GET", "/compliance/cases?state=all", nil, nil)
	if caseID := str(field(cases, "data", "0", "case_id")); caseID != "" {
		c.do("GET", "/compliance/cases/{caseId}", []string{caseID}, nil)
		c.do("GET", "/compliance/cases/{caseId}/drafts/{track}", []string{caseID, "certin"}, nil)
		c.do("GET", "/compliance/cases/{caseId}/drafts/{track}", []string{caseID, "dpdp_report"}, nil)
		sub := map[string]any{"submitted_at": "2026-09-29T08:40:00Z", "reference": "CERTIN-2026-000123"}
		if code, _, b := c.do("POST", "/compliance/cases/{caseId}/tracks/{track}/submission", []string{caseID, "certin"}, sub); code != 201 {
			t.Fatalf("submission: %d %s", code, b)
		}
		if code, _, _ := c.do("POST", "/compliance/cases/{caseId}/tracks/{track}/submission", []string{caseID, "certin"}, sub); code != 409 {
			t.Fatal("second submission must be 409")
		}
	} else {
		t.Error("seed 42 should open a compliance case")
	}
	c.do("GET", "/governance/retention", nil, nil)

	// evaluation and audit
	if code, _, b := c.do("POST", "/evaluations", nil, map[string]any{"run_id": runID}); code != 201 {
		t.Fatalf("evaluation: %d %s", code, b)
	}
	c.do("GET", "/evaluations/latest?dataset_id="+ds, nil, nil)
	_, _, au := c.do("GET", "/audit?limit=5", nil, nil)
	c.do("GET", "/audit?limit=5&cursor="+str(field(au, "page", "next_cursor")), nil, nil)
	if _, _, v := c.do("GET", "/audit/verify", nil, nil); field(v, "ok") != true {
		t.Fatalf("audit chain: %s", v)
	}

	// adversary bench
	code, _, b = c.do("POST", "/adversary/campaigns", nil, map[string]any{"base_dataset": ds, "strategy": "supernode_laundering", "budgets": []float64{0, 1}})
	if code != 202 {
		t.Fatalf("campaign: %d %s", code, b)
	}
	camp := str(field(b, "campaign_id"))
	for i := 0; i < 200; i++ {
		_, _, cb := c.do("GET", "/adversary/campaigns/{campaignId}", []string{camp}, nil)
		if s := str(field(cb, "status")); s == "succeeded" || s == "failed" {
			if s == "failed" {
				t.Fatalf("campaign failed: %s", cb)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.do("GET", "/adversary/campaigns", nil, nil)
	_, _, curve := c.do("GET", "/adversary/curve?base_dataset="+ds, nil, nil)
	if len(field(curve, "series").([]any)) == 0 {
		t.Fatalf("curve has no series: %s", curve)
	}
	if code, _, _ := c.do("POST", "/adversary/campaigns", nil, map[string]any{"base_dataset": "ds_ext_upload", "strategy": "noise_flood"}); code != 422 {
		t.Fatal("a campaign without ground truth must be 422")
	}

	// roles
	_, _, lb := c.do("POST", "/auth/login", nil, map[string]string{"username": "analyst", "password": "analyst-pw"})
	an := &client{t: t, base: srv.URL, spec: sp, token: str(field(lb, "access_token"))}
	if code, _, _ := an.do("POST", "/runs", nil, map[string]any{"dataset_id": ds}); code != 403 {
		t.Fatal("an analyst cannot start runs")
	}
	if code, _, _ := an.do("GET", "/incidents?dataset_id="+ds, nil, nil); code != 200 {
		t.Fatal("an analyst can read the queue")
	}
}

// The validator itself must reject bodies that break the contract, or a green
// contract run proves nothing.
func TestSpecValidatorRejectsViolations(t *testing.T) {
	sp := loadSpec(t)
	bad := []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/meta", 200, `{"version":"x"}`},                                                        // missing required fields
		{"GET", "/incidents/{incidentId}/cohesion", 200, `{"incident_id":"INC-1","cohesion":"wobbly","bridge_edges":[]}`}, // bad pattern and enum
		{"GET", "/runs/{runId}/receipt", 404, `{"code":"NOT_FOUND"}`},                                    // problem without required fields
	}
	for _, b := range bad {
		inner := &testing.T{}
		sp.validate(inner, b.method, b.path, b.status, []byte(b.body))
		if !inner.Failed() {
			t.Errorf("%s %s %d accepted an invalid body: %s", b.method, b.path, b.status, b.body)
		}
	}
}

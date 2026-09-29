-- Prahari schema, Postgres dialect. The SQLite migration with the same number
-- defines the same logical schema; CI fails if the two directories diverge.

CREATE TABLE users (
  user_id       TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('analyst', 'lead')),
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE assets (
  hostname     TEXT PRIMARY KEY,
  role         TEXT NOT NULL,
  criticality  SMALLINT NOT NULL CHECK (criticality BETWEEN 1 AND 10),
  data_classes JSONB NOT NULL DEFAULT '[]',
  owner        TEXT,
  updated_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE datasets (
  dataset_id         TEXT PRIMARY KEY,
  kind               TEXT NOT NULL CHECK (kind IN ('simulated', 'ingested', 'adversarial')),
  seed               BIGINT,
  window_start       TIMESTAMPTZ NOT NULL,
  window_end         TIMESTAMPTZ NOT NULL,
  scenarios          JSONB NOT NULL DEFAULT '[]',
  has_truth          BOOLEAN NOT NULL DEFAULT false,
  parent_id          TEXT REFERENCES datasets (dataset_id),
  current_run_id     TEXT,
  auth_events        INTEGER NOT NULL DEFAULT 0,
  alerts             INTEGER NOT NULL DEFAULT 0,
  alerts_by_detector INTEGER NOT NULL DEFAULT 0,
  created_at         TIMESTAMPTZ NOT NULL
);

-- Log tables are partitioned monthly on ts. All three share boundaries so
-- retention drops them together; an unpartitioned entity index would orphan
-- rows forever and the governance view would report a policy the database was
-- not honouring.
CREATE TABLE auth_events (
  dataset_id TEXT NOT NULL,
  event_id   TEXT NOT NULL,
  ts         TIMESTAMPTZ NOT NULL,
  username   TEXT NOT NULL,
  src_ip     TEXT NOT NULL,
  geo        TEXT NOT NULL DEFAULT '',
  result     TEXT NOT NULL,
  app        TEXT NOT NULL,
  is_admin   BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (dataset_id, event_id, ts)
) PARTITION BY RANGE (ts);
CREATE INDEX auth_events_ds_ts ON auth_events (dataset_id, ts);

CREATE TABLE alerts (
  dataset_id   TEXT NOT NULL,
  id           TEXT NOT NULL,
  ts           TIMESTAMPTZ NOT NULL,
  source       TEXT NOT NULL,
  rule_id      TEXT NOT NULL,
  rule_name    TEXT NOT NULL,
  severity     TEXT NOT NULL,
  technique_id TEXT NOT NULL DEFAULT '',
  entities     JSONB NOT NULL,
  raw          JSONB NOT NULL,
  PRIMARY KEY (dataset_id, id, ts)
) PARTITION BY RANGE (ts);
CREATE INDEX alerts_ds_ts ON alerts (dataset_id, ts, id);
CREATE INDEX alerts_ds_id ON alerts (dataset_id, id);

-- The primary key is the linking index: (dataset_id, entity_key, ts) is the
-- order the LAG() edge query scans.
CREATE TABLE alert_entities (
  dataset_id TEXT NOT NULL,
  entity_key TEXT NOT NULL,
  alert_id   TEXT NOT NULL,
  ts         TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (dataset_id, entity_key, ts, alert_id)
) PARTITION BY RANGE (ts);

CREATE TABLE runs (
  run_id         TEXT PRIMARY KEY,
  dataset_id     TEXT NOT NULL REFERENCES datasets (dataset_id),
  status         TEXT NOT NULL,
  requested_by   TEXT NOT NULL,
  params         JSONB NOT NULL,
  summary        JSONB,
  error          TEXT,
  input_hash     TEXT,
  config_hash    TEXT,
  output_hash    TEXT,
  engine_version TEXT,
  attack_version TEXT,
  dialect        TEXT,
  bands          JSONB,
  created_at     TIMESTAMPTZ NOT NULL,
  started_at     TIMESTAMPTZ,
  finished_at    TIMESTAMPTZ,
  computed_at    TIMESTAMPTZ
);
CREATE INDEX runs_ds_created ON runs (dataset_id, created_at DESC);

-- Run exclusivity is a row, not an advisory lock: identical on both dialects
-- and a crashed process is recovered by the TTL reaper.
CREATE TABLE run_locks (
  dataset_id  TEXT PRIMARY KEY,
  run_id      TEXT NOT NULL,
  acquired_at TIMESTAMPTZ NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL
);

-- Incidents are immutable per run and keyed (run_id, id): IDs are content
-- derived and stable across rebuilds, so the same ID appears in many runs.
CREATE TABLE incidents (
  run_id      TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
  id          TEXT NOT NULL,
  rank        INTEGER NOT NULL,
  label       TEXT NOT NULL,
  headline    TEXT NOT NULL,
  risk        DOUBLE PRECISION NOT NULL,
  priority    TEXT NOT NULL,
  cohesion    TEXT NOT NULL,
  max_stage   SMALLINT NOT NULL,
  first_seen  TIMESTAMPTZ NOT NULL,
  last_seen   TIMESTAMPTZ NOT NULL,
  alert_count INTEGER NOT NULL,
  has_breach  BOOLEAN NOT NULL,
  summary     JSONB NOT NULL,   -- the queue row: no graph or timeline
  detail      JSONB NOT NULL,   -- the full incident
  facts_hash  TEXT NOT NULL,
  PRIMARY KEY (run_id, id)
);
CREATE INDEX incidents_run_rank ON incidents (run_id, rank);

CREATE TABLE incident_alerts (
  run_id      TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  alert_id    TEXT NOT NULL,
  on_chain    BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (run_id, incident_id, alert_id)
);

-- Analyst state keyed on the stable ID only, so verdicts survive a re-run.
CREATE TABLE incident_state (
  incident_id TEXT PRIMARY KEY,
  status      TEXT NOT NULL DEFAULT 'open',
  assignee    TEXT,
  version     INTEGER NOT NULL DEFAULT 1,
  updated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE narratives (
  facts_hash   TEXT PRIMARY KEY,
  incident_id  TEXT NOT NULL,
  source       TEXT NOT NULL,
  model        TEXT,
  attempts     INTEGER NOT NULL,
  body         JSONB NOT NULL,
  validation   JSONB NOT NULL,
  generated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE rule_stats (
  rule_id         TEXT PRIMARY KEY,
  rule_name       TEXT NOT NULL,
  source          TEXT NOT NULL,
  technique_id    TEXT NOT NULL DEFAULT '',
  alpha           DOUBLE PRECISION NOT NULL,
  beta            DOUBLE PRECISION NOT NULL,
  confirmed       INTEGER NOT NULL DEFAULT 0,
  false_positives INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE suppressions (
  suppression_id BIGSERIAL PRIMARY KEY,
  rule_id        TEXT NOT NULL,
  entity_key     TEXT NOT NULL,
  reason         TEXT,
  created_by     TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL,
  expires_at     TIMESTAMPTZ,
  UNIQUE (rule_id, entity_key)
);

CREATE TABLE feedback (
  feedback_id BIGSERIAL PRIMARY KEY,
  incident_id TEXT NOT NULL,
  run_id      TEXT NOT NULL,
  verdict     TEXT NOT NULL CHECK (verdict IN ('confirmed', 'false_positive')),
  note        TEXT,
  user_id     TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX feedback_incident ON feedback (incident_id, created_at DESC);

-- Analyst-recorded splits: every later run of the dataset honours them.
CREATE TABLE dataset_cuts (
  dataset_id  TEXT NOT NULL,
  alert_a     TEXT NOT NULL,
  alert_b     TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (dataset_id, alert_a, alert_b)
);

CREATE TABLE compliance_cases (
  case_id       TEXT PRIMARY KEY,
  incident_id   TEXT NOT NULL UNIQUE,
  dataset_id    TEXT NOT NULL,
  run_id        TEXT NOT NULL,
  priority      TEXT NOT NULL,
  headline      TEXT NOT NULL,
  detected_at   TIMESTAMPTZ NOT NULL,   -- frozen; never recomputed
  trigger       JSONB NOT NULL,
  evidence_hash TEXT NOT NULL
);

CREATE TABLE compliance_tracks (
  case_id      TEXT NOT NULL REFERENCES compliance_cases (case_id),
  track        TEXT NOT NULL CHECK (track IN ('certin', 'dpdp_intimation', 'dpdp_report')),
  deadline     TIMESTAMPTZ NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  draft        JSONB,
  generated_at TIMESTAMPTZ,
  submitted_at TIMESTAMPTZ,
  submitted_by TEXT,
  reference    TEXT,
  note         TEXT,
  PRIMARY KEY (case_id, track)
);

-- Hash-chained, append-only. audit_head serialises appends so seq is gapless
-- under concurrency on both dialects.
CREATE TABLE audit_head (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  seq  BIGINT NOT NULL,
  hash TEXT NOT NULL
);
INSERT INTO audit_head (id, seq, hash) VALUES (1, 0, repeat('0', 64));

CREATE TABLE audit_log (
  seq       BIGINT PRIMARY KEY,
  ts        TIMESTAMPTZ NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  subject   TEXT,
  payload   JSONB NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
CREATE INDEX audit_subject ON audit_log (subject, seq DESC);

-- Tamper-evident, not tamper-proof: a superuser can drop this trigger and
-- rewrite the chain, which is why the head hash should be exported off-box.
CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TABLE evasion_campaigns (
  campaign_id  TEXT PRIMARY KEY,
  base_dataset TEXT NOT NULL REFERENCES datasets (dataset_id),
  strategy     TEXT NOT NULL CHECK (strategy IN ('entity_rotation', 'temporal_dilation', 'supernode_laundering', 'noise_flood')),
  budgets      JSONB NOT NULL,
  mitigated    BOOLEAN NOT NULL DEFAULT false,
  seed         BIGINT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'queued',
  created_by   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL,
  finished_at  TIMESTAMPTZ,
  duration_ms  BIGINT,
  error        TEXT
);

CREATE TABLE evasion_results (
  campaign_id         TEXT NOT NULL REFERENCES evasion_campaigns (campaign_id),
  budget              DOUBLE PRECISION NOT NULL,
  variant_dataset     TEXT NOT NULL REFERENCES datasets (dataset_id),
  run_id              TEXT NOT NULL REFERENCES runs (run_id),
  scenario_recall     DOUBLE PRECISION NOT NULL,
  pairwise_precision  DOUBLE PRECISION NOT NULL,
  pairwise_recall     DOUBLE PRECISION NOT NULL,
  incidents           INTEGER NOT NULL,
  detected            BOOLEAN NOT NULL,
  top_rank            INTEGER,
  scenarios_evaluated INTEGER NOT NULL,
  PRIMARY KEY (campaign_id, budget)
);

CREATE TABLE evaluations (
  evaluation_id TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs (run_id),
  dataset_id    TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL,
  body          JSONB NOT NULL
);
CREATE INDEX evaluations_ds ON evaluations (dataset_id, created_at DESC);

CREATE TABLE idempotency_keys (
  user_id    TEXT NOT NULL,
  route      TEXT NOT NULL,
  key        TEXT NOT NULL,
  body_hash  TEXT NOT NULL,
  status     INTEGER NOT NULL,
  headers    JSONB NOT NULL,
  body       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, route, key)
);

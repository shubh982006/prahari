-- Prahari schema, SQLite dialect: the same logical schema as the Postgres
-- migration with the same number, as STRICT tables. JSON is TEXT, booleans are
-- INTEGER 0/1, timestamps are fixed-width RFC 3339 TEXT so they sort.
-- No partitioning: retention is DELETE by timestamp (a documented degradation).

CREATE TABLE users (
  user_id       TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('analyst', 'lead')),
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;

CREATE TABLE assets (
  hostname     TEXT PRIMARY KEY,
  role         TEXT NOT NULL,
  criticality  INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 10),
  data_classes TEXT NOT NULL DEFAULT '[]',
  owner        TEXT,
  updated_at   TEXT NOT NULL
) STRICT;

CREATE TABLE datasets (
  dataset_id         TEXT PRIMARY KEY,
  kind               TEXT NOT NULL CHECK (kind IN ('simulated', 'ingested', 'adversarial')),
  seed               INTEGER,
  window_start       TEXT NOT NULL,
  window_end         TEXT NOT NULL,
  scenarios          TEXT NOT NULL DEFAULT '[]',
  has_truth          INTEGER NOT NULL DEFAULT 0,
  parent_id          TEXT REFERENCES datasets (dataset_id),
  current_run_id     TEXT,
  auth_events        INTEGER NOT NULL DEFAULT 0,
  alerts             INTEGER NOT NULL DEFAULT 0,
  alerts_by_detector INTEGER NOT NULL DEFAULT 0,
  created_at         TEXT NOT NULL
) STRICT;

-- On Postgres these three tables are partitioned monthly; here retention
-- deletes by ts across all three together, because an unpartitioned entity index would orphan
-- rows forever and the governance view would report a policy the database was
-- not honouring.
CREATE TABLE auth_events (
  dataset_id TEXT NOT NULL,
  event_id   TEXT NOT NULL,
  ts         TEXT NOT NULL,
  username   TEXT NOT NULL,
  src_ip     TEXT NOT NULL,
  geo        TEXT NOT NULL DEFAULT '',
  result     TEXT NOT NULL,
  app        TEXT NOT NULL,
  is_admin   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (dataset_id, event_id, ts)
) STRICT;
CREATE INDEX auth_events_ds_ts ON auth_events (dataset_id, ts);

CREATE TABLE alerts (
  dataset_id   TEXT NOT NULL,
  id           TEXT NOT NULL,
  ts           TEXT NOT NULL,
  source       TEXT NOT NULL,
  rule_id      TEXT NOT NULL,
  rule_name    TEXT NOT NULL,
  severity     TEXT NOT NULL,
  technique_id TEXT NOT NULL DEFAULT '',
  entities     TEXT NOT NULL,
  raw          TEXT NOT NULL,
  PRIMARY KEY (dataset_id, id, ts)
) STRICT;
CREATE INDEX alerts_ds_ts ON alerts (dataset_id, ts, id);
CREATE INDEX alerts_ds_id ON alerts (dataset_id, id);

-- The primary key is the linking index: (dataset_id, entity_key, ts) is the
-- order the LAG() edge query scans.
CREATE TABLE alert_entities (
  dataset_id TEXT NOT NULL,
  entity_key TEXT NOT NULL,
  alert_id   TEXT NOT NULL,
  ts         TEXT NOT NULL,
  PRIMARY KEY (dataset_id, entity_key, ts, alert_id)
) STRICT;

CREATE TABLE runs (
  run_id         TEXT PRIMARY KEY,
  dataset_id     TEXT NOT NULL REFERENCES datasets (dataset_id),
  status         TEXT NOT NULL,
  requested_by   TEXT NOT NULL,
  params         TEXT NOT NULL,
  summary        TEXT,
  error          TEXT,
  input_hash     TEXT,
  config_hash    TEXT,
  output_hash    TEXT,
  engine_version TEXT,
  attack_version TEXT,
  dialect        TEXT,
  bands          TEXT,
  created_at     TEXT NOT NULL,
  started_at     TEXT,
  finished_at    TEXT,
  computed_at    TEXT
) STRICT;
CREATE INDEX runs_ds_created ON runs (dataset_id, created_at);

-- Run exclusivity is a row, not an advisory lock: identical on both dialects
-- and a crashed process is recovered by the TTL reaper.
CREATE TABLE run_locks (
  dataset_id  TEXT PRIMARY KEY,
  run_id      TEXT NOT NULL,
  acquired_at TEXT NOT NULL,
  expires_at  TEXT NOT NULL
) STRICT;

-- Incidents are immutable per run and keyed (run_id, id): IDs are content
-- derived and stable across rebuilds, so the same ID appears in many runs.
CREATE TABLE incidents (
  run_id      TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
  id          TEXT NOT NULL,
  rank        INTEGER NOT NULL,
  label       TEXT NOT NULL,
  headline    TEXT NOT NULL,
  risk        REAL NOT NULL,
  priority    TEXT NOT NULL,
  cohesion    TEXT NOT NULL,
  max_stage   INTEGER NOT NULL,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  alert_count INTEGER NOT NULL,
  has_breach  INTEGER NOT NULL,
  summary     TEXT NOT NULL,   -- the queue row: no graph or timeline
  detail      TEXT NOT NULL,   -- the full incident
  facts_hash  TEXT NOT NULL,
  PRIMARY KEY (run_id, id)
) STRICT;
CREATE INDEX incidents_run_rank ON incidents (run_id, rank);

CREATE TABLE incident_alerts (
  run_id      TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  alert_id    TEXT NOT NULL,
  on_chain    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id, incident_id, alert_id)
) STRICT;

-- Analyst state keyed on the stable ID only, so verdicts survive a re-run.
CREATE TABLE incident_state (
  incident_id TEXT PRIMARY KEY,
  status      TEXT NOT NULL DEFAULT 'open',
  assignee    TEXT,
  version     INTEGER NOT NULL DEFAULT 1,
  updated_at  TEXT NOT NULL
) STRICT;

CREATE TABLE narratives (
  facts_hash   TEXT PRIMARY KEY,
  incident_id  TEXT NOT NULL,
  source       TEXT NOT NULL,
  model        TEXT,
  attempts     INTEGER NOT NULL,
  body         TEXT NOT NULL,
  validation   TEXT NOT NULL,
  generated_at TEXT NOT NULL
) STRICT;

CREATE TABLE rule_stats (
  rule_id         TEXT PRIMARY KEY,
  rule_name       TEXT NOT NULL,
  source          TEXT NOT NULL,
  technique_id    TEXT NOT NULL DEFAULT '',
  alpha           REAL NOT NULL,
  beta            REAL NOT NULL,
  confirmed       INTEGER NOT NULL DEFAULT 0,
  false_positives INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE suppressions (
  suppression_id INTEGER PRIMARY KEY,
  rule_id        TEXT NOT NULL,
  entity_key     TEXT NOT NULL,
  reason         TEXT,
  created_by     TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  expires_at     TEXT,
  UNIQUE (rule_id, entity_key)
) STRICT;

CREATE TABLE feedback (
  feedback_id INTEGER PRIMARY KEY,
  incident_id TEXT NOT NULL,
  run_id      TEXT NOT NULL,
  verdict     TEXT NOT NULL CHECK (verdict IN ('confirmed', 'false_positive')),
  note        TEXT,
  user_id     TEXT NOT NULL,
  created_at  TEXT NOT NULL
) STRICT;
CREATE INDEX feedback_incident ON feedback (incident_id, created_at);

-- Analyst-recorded splits: every later run of the dataset honours them.
CREATE TABLE dataset_cuts (
  dataset_id  TEXT NOT NULL,
  alert_a     TEXT NOT NULL,
  alert_b     TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (dataset_id, alert_a, alert_b)
) STRICT;

CREATE TABLE compliance_cases (
  case_id       TEXT PRIMARY KEY,
  incident_id   TEXT NOT NULL UNIQUE,
  dataset_id    TEXT NOT NULL,
  run_id        TEXT NOT NULL,
  priority      TEXT NOT NULL,
  headline      TEXT NOT NULL,
  detected_at   TEXT NOT NULL,   -- frozen; never recomputed
  trigger       TEXT NOT NULL,
  evidence_hash TEXT NOT NULL
);

CREATE TABLE compliance_tracks (
  case_id      TEXT NOT NULL REFERENCES compliance_cases (case_id),
  track        TEXT NOT NULL CHECK (track IN ('certin', 'dpdp_intimation', 'dpdp_report')),
  deadline     TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  draft        TEXT,
  generated_at TEXT,
  submitted_at TEXT,
  submitted_by TEXT,
  reference    TEXT,
  note         TEXT,
  PRIMARY KEY (case_id, track)
) STRICT;

-- Hash-chained, append-only. audit_head serialises appends so seq is gapless
-- under concurrency on both dialects.
CREATE TABLE audit_head (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  seq  INTEGER NOT NULL,
  hash TEXT NOT NULL
) STRICT;
INSERT INTO audit_head (id, seq, hash) VALUES (1, 0, '0000000000000000000000000000000000000000000000000000000000000000');

CREATE TABLE audit_log (
  seq       INTEGER PRIMARY KEY,
  ts        TEXT NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  subject   TEXT,
  payload   TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
) STRICT;
CREATE INDEX audit_subject ON audit_log (subject, seq);

-- Tamper-evident, not tamper-proof: anyone with the file can drop these
-- triggers and rewrite the chain, which is why the head hash should be exported off-box.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE evasion_campaigns (
  campaign_id  TEXT PRIMARY KEY,
  base_dataset TEXT NOT NULL REFERENCES datasets (dataset_id),
  strategy     TEXT NOT NULL CHECK (strategy IN ('entity_rotation', 'temporal_dilation', 'supernode_laundering', 'noise_flood')),
  budgets      TEXT NOT NULL,
  mitigated    INTEGER NOT NULL DEFAULT 0,
  seed         INTEGER NOT NULL,
  status       TEXT NOT NULL DEFAULT 'queued',
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  finished_at  TEXT,
  duration_ms  INTEGER,
  error        TEXT
) STRICT;

CREATE TABLE evasion_results (
  campaign_id         TEXT NOT NULL REFERENCES evasion_campaigns (campaign_id),
  budget              REAL NOT NULL,
  variant_dataset     TEXT NOT NULL REFERENCES datasets (dataset_id),
  run_id              TEXT NOT NULL REFERENCES runs (run_id),
  scenario_recall     REAL NOT NULL,
  pairwise_precision  REAL NOT NULL,
  pairwise_recall     REAL NOT NULL,
  incidents           INTEGER NOT NULL,
  detected            INTEGER NOT NULL,
  top_rank            INTEGER,
  scenarios_evaluated INTEGER NOT NULL,
  PRIMARY KEY (campaign_id, budget)
) STRICT;

CREATE TABLE evaluations (
  evaluation_id TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs (run_id),
  dataset_id    TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  body          TEXT NOT NULL
) STRICT;
CREATE INDEX evaluations_ds ON evaluations (dataset_id, created_at);

CREATE TABLE idempotency_keys (
  user_id    TEXT NOT NULL,
  route      TEXT NOT NULL,
  key        TEXT NOT NULL,
  body_hash  TEXT NOT NULL,
  status     INTEGER NOT NULL,
  headers    TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, route, key)
) STRICT;

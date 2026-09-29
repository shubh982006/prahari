# Prahari — API Contract v1

**Version** 2.0 · 29 Sep 2026 · **supersedes** the v1.0 contract
**Machine-readable source of truth:** [`openapi.yaml`](./openapi.yaml) — if the two disagree, **the YAML wins** and this file gets fixed.

New in this version: cohesion and split (§8), counterfactuals (§9), determinism receipts (§10), the adversary bench (§11). Changed: incident identity is now `(run_id, incident_id)`, compliance has three tracks, priority bands are calibrated per run.

---

## Contents

1. [Conventions](#1-conventions) · 2. [Endpoint index](#2-endpoint-index) · 3. [Auth](#3-auth)
4. [Datasets and ingest](#4-datasets-and-ingest) · 5. [Alerts](#5-alerts) · 6. [Runs and SSE](#6-runs-and-sse)
7. [Incidents](#7-incidents) · 8. [Cohesion and split](#8-cohesion-and-split) · 9. [Counterfactuals](#9-counterfactuals)
10. [Receipts](#10-receipts) · 11. [Adversary bench](#11-adversary-bench) · 12. [Feedback and rules](#12-feedback-and-rules)
13. [Assets](#13-assets) · 14. [Compliance](#14-compliance) · 15. [Evaluations](#15-evaluations)
16. [Audit](#16-audit) · 17. [System](#17-system) · 18. [Error catalogue](#18-error-catalogue)
19. [Frontend integration](#19-frontend-integration) · 20. [Contract workflow](#20-contract-workflow)

---

## 1. Conventions

### 1.1 Base and versioning

Base `http://localhost:8080/api/v1` (via nginx) or `:8000` (Go direct). Version in the path. Additive changes stay in `v1`; renames or changed meaning require `v2`. **Clients must ignore unknown fields.**

### 1.2 Formats

| Thing | Rule |
|---|---|
| Bodies | `application/json; charset=utf-8` |
| Bulk ingest | `application/x-ndjson` — one object per line |
| Streams | `text/event-stream` |
| Errors | `application/problem+json` (RFC 9457) |
| Fields | `snake_case` |
| Timestamps | UTC RFC 3339 (`2026-09-29T04:35:12Z`); the UI renders IST |
| Durations | Go duration strings (`2h`, `90m`) |
| Scores | Numbers, 2 decimal places |
| Nulls | Optional fields may be `null` or absent; treat both as unset |

### 1.3 Auth and roles

`POST /auth/login` returns a JWT; send `Authorization: Bearer <token>`. Lifetime 1 h; on `401 TOKEN_EXPIRED` return to login.

**SSE exception:** `EventSource` cannot set headers, so SSE endpoints *also* accept `?access_token=<jwt>`. Only those endpoints.

Roles: `analyst` (read + triage) and `lead` (everything). Endpoints marked 🔒 require `lead`.

### 1.4 Pagination

Cursor (keyset), not offset — stable while new data arrives, fast on large tables.

```http
GET /api/v1/alerts?dataset_id=ds_20260929_s42&severity=high,critical&limit=50&cursor=eyJ0cyI6…
```

```json
{ "data": [ … ], "page": { "limit": 50, "next_cursor": "eyJ0cyI6…" } }
```

`limit` 1–500, default 50. `next_cursor: null` means last page. Multi-value filters are comma-separated. `sort` takes a `-` prefix for descending.

### 1.5 Concurrency

| Header | Where | Behaviour |
|---|---|---|
| `Idempotency-Key: <uuid>` | `POST /runs`, `POST /incidents/{id}/feedback`, `POST /adversary/campaigns` | Same key + same body within 24 h replays the stored response; same key + different body ⇒ `409 IDEMPOTENCY_KEY_REUSED` |
| `ETag` / `If-None-Match` | `GET /incidents`, `GET /incidents/{id}` | `304` when unchanged |
| `If-Match` | `PATCH /incidents/{id}` (**required**) | Missing ⇒ `428`; stale ⇒ `412` |

### 1.6 Errors

```json
{
  "type": "https://prahari.dev/problems/validation-failed",
  "title": "Request validation failed",
  "status": 400,
  "detail": "2 fields are invalid",
  "instance": "/api/v1/incidents/INC-3f9a1c2e/feedback",
  "code": "VALIDATION_FAILED",
  "request_id": "req_01J8ZK6W4T2Q",
  "errors": [
    { "field": "body.verdict", "message": "must be one of: confirmed, false_positive" }
  ]
}
```

`code` is the stable machine-readable value — **the UI switches on `code`, never on `title`**. `request_id` also returns as the `X-Request-ID` header.

### 1.7 Rate limits

| Class | Limit |
|---|---|
| login | 10/min per IP |
| narrative regeneration | 10/min per user |
| adversary campaign creation | 6/min per user |
| default | 300/min per user |

Responses carry `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`; `429` carries `Retry-After`.

---

## 2. Endpoint index

| # | Method | Path | Role | Purpose |
|---|---|---|---|---|
| 1 | POST | `/auth/login` | public | Get a JWT |
| 2 | GET | `/auth/me` | any | Current user |
| 3 | GET | `/meta` | any | Version, dialect, ATT&CK version, engine config |
| 4 | POST | `/simulations` | 🔒 | Generate + ingest a synthetic dataset |
| 5 | GET | `/datasets` | any | List datasets |
| 6 | POST | `/datasets` | 🔒 | Register an empty dataset for external ingest |
| 7 | GET | `/datasets/{id}` | any | Dataset detail |
| 8 | POST | `/datasets/{id}/auth-events` | 🔒 | NDJSON auth logs → detectors |
| 9 | POST | `/datasets/{id}/alerts` | 🔒 | NDJSON alerts |
| 10 | GET | `/alerts` | any | Firehose feed |
| 11 | GET | `/alerts/stats` | any | Counts by source / severity / hour |
| 12 | GET | `/alerts/{id}` | any | One alert with raw payload |
| 13 | GET | `/runs` | any | Run history |
| 14 | POST | `/runs` | 🔒 | Start correlation (async) |
| 15 | GET | `/runs/{id}` | any | Run status + summary |
| 16 | POST | `/runs/{id}/cancel` | 🔒 | Cancel |
| 17 | GET | `/runs/{id}/events` | any | **SSE** run progress |
| 18 | **GET** | **`/runs/{id}/receipt`** | any | **Determinism receipt** |
| 19 | GET | `/events` | any | **SSE** global notifications |
| 20 | GET | `/incidents` | any | Ranked queue |
| 21 | GET | `/incidents/{id}` | any | Detail + risk breakdown + cohesion |
| 22 | PATCH | `/incidents/{id}` | any | Status / assignee |
| 23 | GET | `/incidents/{id}/alerts` | any | Member alerts |
| 24 | GET | `/incidents/{id}/graph` | any | Entity graph (React Flow) |
| 25 | GET | `/incidents/{id}/timeline` | any | Kill-chain swim-lanes |
| 26 | GET | `/incidents/{id}/narrative` | any | Grounded brief |
| 27 | POST | `/incidents/{id}/narrative/regenerate` | any | Bypass cache |
| 28 | **GET** | **`/incidents/{id}/cohesion`** | any | **Bridges + split preview** |
| 29 | **POST** | **`/incidents/{id}/split`** | 🔒 | **Materialise the split** |
| 30 | **GET** | **`/incidents/{id}/counterfactuals`** | any | **What would change this** |
| 31 | GET | `/incidents/{id}/feedback` | any | Verdict history |
| 32 | POST | `/incidents/{id}/feedback` | any (suppress 🔒) | Record verdict |
| 33 | GET | `/rules` | any | Rules + learned precision |
| 34 | GET | `/suppressions` | any | Active suppressions |
| 35 | DELETE | `/suppressions/{id}` | 🔒 | Remove suppression |
| 36 | GET | `/assets` | any | CMDB |
| 37 | GET | `/assets/{hostname}` | any | One asset |
| 38 | PUT | `/assets/{hostname}` | 🔒 | Create/replace asset |
| 39 | **POST** | **`/adversary/campaigns`** | 🔒 | **Run an evasion campaign** |
| 40 | **GET** | **`/adversary/campaigns`** | any | **List campaigns** |
| 41 | **GET** | **`/adversary/campaigns/{id}`** | any | **Campaign + per-budget results** |
| 42 | **GET** | **`/adversary/campaigns/{id}/events`** | any | **SSE** campaign progress |
| 43 | **GET** | **`/adversary/curve`** | any | **The evasion curve, plot-ready** |
| 44 | GET | `/compliance/cases` | any | Cases + live deadlines |
| 45 | GET | `/compliance/cases/{id}` | any | Case + evidence timeline |
| 46 | GET | `/compliance/cases/{id}/drafts/{track}` | any | Draft report |
| 47 | POST | `/compliance/cases/{id}/tracks/{track}/submission` | 🔒 | Record human submission |
| 48 | GET | `/governance/retention` | any | 180-day retention state |
| 49 | POST | `/evaluations` | 🔒 | Score a run vs ground truth |
| 50 | GET | `/evaluations/latest` | any | Latest metrics |
| 51 | GET | `/audit` | any | Audit trail |
| 52 | GET | `/audit/verify` | any | Verify hash chain |
| — | GET | `/healthz` `/readyz` `/metrics` | internal | Ops (no `/api/v1` prefix) |

---

## 3. Auth

### `POST /auth/login`

```json
{ "username": "meow", "password": "••••••••" }
```

**200**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": { "user_id": "u_meow", "display_name": "Meow", "role": "lead" }
}
```

**401** `INVALID_CREDENTIALS` — identical message for unknown user and wrong password, so the endpoint cannot be used to enumerate accounts. **429** `RATE_LIMITED`.

JWT claims: `sub`, `role`, `iat`, `exp`, `jti`.

### `GET /auth/me` → `User`

---

## 4. Datasets and ingest

### `POST /simulations` 🔒

```json
{
  "seed": 42,
  "start": "2026-09-28T18:30:00Z",
  "hours": 24,
  "scenarios": ["A","B","C","D","E","F"],
  "noise_level": "normal",
  "users": 60
}
```

**201** `Location: /api/v1/datasets/ds_20260929_s42`
```json
{
  "dataset_id": "ds_20260929_s42",
  "kind": "simulated",
  "seed": 42,
  "window_start": "2026-09-28T18:30:00Z",
  "window_end": "2026-09-29T18:30:00Z",
  "scenarios": ["A","B","C","D","E","F"],
  "counts": { "auth_events": 21480, "alerts": 3000, "alerts_by_detector": 212 },
  "has_truth": true,
  "parent_id": null,
  "current_run_id": null,
  "created_at": "2026-09-29T06:28:44Z"
}
```

**409** `ALREADY_EXISTS` when the same seed + start exists; the existing dataset is named in `detail`.

Ground truth is written to `data/truth/<dataset_id>.json` and is **never** returned by this API nor read by the engine.

### `POST /datasets/{id}/auth-events` 🔒

```http
Content-Type: application/x-ndjson

{"event_id":"AE-1","timestamp":"2026-09-29T03:32:11Z","username":"priya@corp.local","src_ip":"185.220.101.7","geo":"NL-AMS","result":"failure","app":"vpn"}
{"event_id":"AE-3","timestamp":"not-a-time","username":"x","src_ip":"1.1.1.1","result":"failure","app":"vpn"}
```

| Field | Type | Req | Notes |
|---|---|---|---|
| `event_id` | string ≤64 | ✅ | Unique within dataset |
| `timestamp` | RFC 3339 | ✅ | |
| `username` | string | ✅ | `DOMAIN\user`, `user@domain` or `USER` — normalised |
| `src_ip` | IPv4/IPv6 | ✅ | |
| `geo` | string | | `IN-DL`, `NL-AMS` — used by impossible travel |
| `result` | `success`\|`failure` | ✅ | |
| `app` | `vpn`\|`o365`\|`rdp`\|`ssh`\|`web` | ✅ | |
| `is_admin` | bool | | Off-hours privileged detector |

**200**
```json
{
  "received": 2, "accepted": 1, "rejected": 1, "duplicates": 0,
  "alerts_raised": 0, "late_events": 0,
  "errors": [ { "line": 2, "field": "timestamp", "message": "must be RFC 3339 date-time" } ],
  "duration_ms": 4
}
```

A bad line never fails the batch; at most 50 errors are listed. **413** if body >50 MB or a line >1 MB. **415** on wrong `Content-Type`.

### `POST /datasets/{id}/alerts` 🔒

Same semantics, one alert per line:

```json
{"id":"ALR-000731","timestamp":"2026-09-29T04:35:12Z","source":"edr","rule_id":"EDR-RDP-LATERAL","rule_name":"RDP session from workstation to domain controller","severity":"high","technique_id":"T1021.001","entities":{"users":["priya@corp.local"],"hosts":["WS-114","DC01"],"ips":["10.1.4.114","10.1.0.10"],"processes":["mstsc.exe"],"hashes":[]},"raw":{"EventID":4624,"LogonType":10}}
```

---

## 5. Alerts

### `GET /alerts`

Query: `dataset_id` (required), `from`, `to`, `source`, `severity`, `rule_id`, `entity` (e.g. `host:dc01`), `q`, `sort` (`ts`|`-ts`), `limit`, `cursor`.

```json
{
  "data": [{
    "dataset_id": "ds_20260929_s42",
    "id": "ALR-000731",
    "timestamp": "2026-09-29T04:35:12Z",
    "source": "edr",
    "rule_id": "EDR-RDP-LATERAL",
    "rule_name": "RDP session from workstation to domain controller",
    "severity": "high",
    "technique_id": "T1021.001",
    "tactic": "Lateral Movement",
    "stage": 4,
    "entities": { "users": ["priya@corp.local"], "hosts": ["WS-114","DC01"], "ips": ["10.1.4.114","10.1.0.10"], "processes": ["mstsc.exe"], "hashes": [] }
  }],
  "page": { "limit": 50, "next_cursor": "eyJ0cyI6…" }
}
```

### `GET /alerts/stats?dataset_id=…`

```json
{
  "total": 3000,
  "by_source":   { "auth": 212, "edr": 1204, "network": 983, "cloud": 431, "email": 170 },
  "by_severity": { "low": 1310, "medium": 1102, "high": 511, "critical": 77 },
  "by_hour": [ { "hour": "2026-09-28T18:00:00Z", "count": 41 } ]
}
```

### `GET /alerts/{id}?dataset_id=…`

`Alert` plus `raw` and normalised `entity_keys`:

```json
{ "…": "all Alert fields",
  "raw": { "EventID": 4624, "LogonType": 10 },
  "entity_keys": ["user:priya@corp.local","host:ws-114","host:dc01","ip:10.1.4.114","process:mstsc.exe"] }
```

---

## 6. Runs and SSE

### `POST /runs` 🔒

```http
POST /api/v1/runs
Idempotency-Key: 5b0e7f0c-2d0c-4d0a-9d34-0f2c1c7a0e11

{ "dataset_id": "ds_20260929_s42" }
```

Optional overrides, validated and snapshotted into the run:

```json
{ "dataset_id": "ds_20260929_s42",
  "overrides": {
    "link_window": "3h",
    "weights": { "C": 0.35, "S": 0.20, "A": 0.30, "Q": 0.15 },
    "capacity": { "p1_per_shift": 5, "p2_per_shift": 10 },
    "laundering_pass": true } }
```

**202** `Location: /api/v1/runs/0192a7c4-…`
```json
{ "run_id": "0192a7c4-6e1b-7c3e-9a51-2f4d7a0c1b11",
  "dataset_id": "ds_20260929_s42",
  "status": "queued", "requested_by": "u_meow",
  "created_at": "2026-09-29T06:31:07Z",
  "started_at": null, "finished_at": null, "is_current": false,
  "summary": null, "error": null,
  "events_url": "/api/v1/runs/0192a7c4-6e1b-7c3e-9a51-2f4d7a0c1b11/events" }
```

**409** `RUN_IN_PROGRESS` — carries `active_run_id`; the UI attaches to that run's SSE instead of failing.
**422** `DATASET_EMPTY`.

### `GET /runs/{id}` — after success

```json
{
  "run_id": "0192a7c4-…", "dataset_id": "ds_20260929_s42",
  "status": "succeeded", "is_current": true,
  "summary": {
    "alerts_in": 3000, "alerts_suppressed": 0, "entity_refs": 11240,
    "stoplisted_entities": ["ip:10.1.0.53","host:proxy01","user:system"],
    "laundering_links_recovered": 0,
    "incidents": 28, "compression_ratio": 107.14,
    "by_priority": { "P1": 4, "P2": 5, "P3": 8, "P4": 11 },
    "by_label": { "attack_chain": 9, "noise_cluster": 7, "single": 12 },
    "by_cohesion": { "solid": 19, "moderate": 6, "fragile": 3 },
    "thresholds": { "P1": 84.10, "P2": 61.04, "P3": 38.22 },
    "cases_opened": 2,
    "stages": [
      { "stage": "load", "count": 3000, "elapsed_ms": 38 },
      { "stage": "filter", "count": 3000, "elapsed_ms": 1 },
      { "stage": "entities", "count": 11240, "elapsed_ms": 9 },
      { "stage": "link", "count": 6121, "elapsed_ms": 7 },
      { "stage": "launder", "count": 0, "elapsed_ms": 1 },
      { "stage": "group", "count": 28, "elapsed_ms": 2 },
      { "stage": "shape", "count": 9, "elapsed_ms": 1 },
      { "stage": "cohesion", "count": 3, "elapsed_ms": 1 },
      { "stage": "score", "count": 4, "elapsed_ms": 1 },
      { "stage": "compliance", "count": 2, "elapsed_ms": 0 },
      { "stage": "commit", "count": 28, "elapsed_ms": 54 }
    ],
    "duration_ms": 115
  }
}
```

> Every number above is an **illustrative placeholder**. Replace with measured values from your own benchmark. Never put an invented number on a slide.

### `GET /runs/{id}/events` — SSE

```http
GET /api/v1/runs/0192a7c4-…/events?access_token=eyJ…
Accept: text/event-stream
Last-Event-ID: 40
```

```
retry: 3000

id: 38
event: status
data: {"run_id":"0192a7c4-…","status":"running"}

id: 39
event: stage
data: {"run_id":"0192a7c4-…","stage":"entities","count":11240,"elapsed_ms":9}

: ping

id: 47
event: done
data: {"run_id":"0192a7c4-…","summary":{ …RunSummary… }}
```

| `event` | `data` | When |
|---|---|---|
| `status` | `{run_id, status}` | queued → running, and on cancel |
| `stage` | `{run_id, stage, count, elapsed_ms}` | after each engine stage |
| `done` | `{run_id, summary}` | commit succeeded; stream closes |
| `error` | `{run_id, code, message}` | run failed; stream closes |
| `: ping` | — | every 15 s |

Events after `Last-Event-ID` are replayed (last 200 kept per run). Connecting to a finished run replays then closes. A slow client is dropped rather than allowed to block the run.

### `GET /events` — global SSE

`event` ∈ `run.started`, `run.finished`, `case.opened`, `incident.updated`, `campaign.finished`.

---

## 7. Incidents

### `GET /incidents`

Query: `dataset_id` (required), `run_id` (defaults to current), `priority`, `label`, `status`, `cohesion`, `asset`, `breach`, `assignee`, `sort` (`-risk` default), `limit`, `cursor`.

**200** `ETag: "run:0192a7c4:state:1727592301"`
```json
{
  "run_id": "0192a7c4-…",
  "totals": { "incidents": 28, "alerts": 3000, "by_priority": { "P1": 4, "P2": 5, "P3": 8, "P4": 11 } },
  "thresholds": { "P1": 84.10, "P2": 61.04, "P3": 38.22 },
  "data": [{
    "incident_id": "INC-3f9a1c2e",
    "run_id": "0192a7c4-…",
    "rank": 1,
    "headline": "Password spray → VPN access → lateral movement to dc01 → exfiltration from fin-db-01",
    "label": "attack_chain",
    "priority": "P1",
    "risk": 98.92,
    "confidence": 0.93,
    "cohesion": "solid",
    "status": "open",
    "assignee": null,
    "alert_count": 37,
    "stages": [1,2,4,6],
    "max_stage": 6,
    "forward_stages": 4,
    "first_seen": "2026-09-29T03:32:11Z",
    "last_seen": "2026-09-29T06:10:44Z",
    "assets": ["dc01","fin-db-01","ws-114"],
    "laundering_inferred": false,
    "has_case": true,
    "case_id": "CASE-0001"
  }],
  "page": { "limit": 50, "next_cursor": null }
}
```

> **Field naming, deliberately.** `confidence` is the noisy-OR factor `Q` in `[0,1]`. `forward_stages` is the LIS integer. These are different things and the UI must not label one as the other — the queue's "Chain 0.93" mislabel came from conflating them.

### `GET /incidents/{id}`

```json
{
  "…": "all summary fields",
  "breakdown": {
    "C": 1.00, "S": 1.00, "A": 1.00, "Q": 0.93,
    "weights": { "C": 0.35, "S": 0.20, "A": 0.30, "Q": 0.15 },
    "risk": 98.92,
    "forward_stages": 4,
    "overrides": ["P1 floor: critical exfiltration on fin-db-01 (criticality 9)"],
    "top_assets": [
      { "hostname": "dc01", "criticality": 10, "data_classes": ["credentials"] },
      { "hostname": "fin-db-01", "criticality": 9, "data_classes": ["pii","financial"] }
    ],
    "rules": [
      { "rule_id": "AUTH-SPRAY", "precision": 0.60, "alerts": 12 },
      { "rule_id": "AUTH-SPRAY-SUCCESS", "precision": 0.80, "alerts": 1 },
      { "rule_id": "EDR-RDP-LATERAL", "precision": 0.60, "alerts": 3 },
      { "rule_id": "NET-EXFIL-LARGE", "precision": 0.40, "alerts": 2 }
    ]
  },
  "entities": [
    { "key": "user:priya@corp.local", "weight": 4.61, "alerts": 30 },
    { "key": "ip:185.220.101.7", "weight": 5.30, "alerts": 13 },
    { "key": "host:dc01", "weight": 3.22, "alerts": 6 }
  ],
  "techniques": [
    { "technique_id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access", "stage": 3, "alerts": 12 },
    { "technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "stage": 6, "alerts": 2 }
  ],
  "sources": { "auth": 13, "edr": 18, "network": 6 },
  "etag": "\"inc:INC-3f9a1c2e:v3\""
}
```

### `PATCH /incidents/{id}`

```http
If-Match: "inc:INC-3f9a1c2e:v3"

{ "status": "investigating", "assignee": "u_meow" }
```

**200** updated detail with a new `ETag`. **412** if someone changed it first. **409** `INVALID_STATE` on an illegal transition. **428** if `If-Match` is missing.

### `GET /incidents/{id}/graph`

Shaped for React Flow; the client applies layout.

```json
{
  "nodes": [
    { "id": "ip:185.220.101.7", "type": "ip", "label": "185.220.101.7", "external": true, "criticality": null, "data_classes": [] },
    { "id": "host:dc01", "type": "host", "label": "DC01", "external": false, "criticality": 10, "data_classes": ["credentials"] }
  ],
  "edges": [
    { "id": "e2", "source": "host:ws-114", "target": "host:dc01",
      "alert_id": "ALR-000731", "ts": "2026-09-29T04:35:12Z",
      "stage": 4, "technique_id": "T1021.001",
      "on_chain": true, "order": 3, "is_bridge": false }
  ]
}
```

`is_bridge` lets the UI draw fragile links differently — it is the same bridge set returned by `/cohesion`.

### `GET /incidents/{id}/timeline`

```json
{
  "lanes": [
    { "stage": 0, "name": "Recon", "tactics": ["Reconnaissance","Resource Development"] },
    { "stage": 6, "name": "Exfiltration & Impact", "tactics": ["Exfiltration","Impact"] }
  ],
  "points": [
    { "alert_id": "ALR-000402", "ts": "2026-09-29T03:37:02Z", "stage": 1,
      "severity": "critical", "rule_name": "Successful login from spraying IP", "on_chain": true }
  ],
  "chain": ["ALR-000402","ALR-000455","ALR-000731","ALR-001102"]
}
```

### `GET /incidents/{id}/narrative`

```json
{
  "incident_id": "INC-3f9a1c2e",
  "facts_hash": "sha256:9b1c…",
  "source": "llm",
  "model": "prahari-narrator",
  "attempts": 1,
  "headline": "Credential spray led to domain controller access and data leaving the finance database",
  "sentences": [
    { "text": "An external IP, 185.220.101.7, attempted logins against 40 accounts within ten minutes.", "citations": ["ALR-000388","ALR-000389"] },
    { "text": "About 2.1 GB left FIN-DB-01 for an unknown external host.", "citations": ["ALR-001102"] }
  ],
  "recommended_actions": [
    { "text": "Disable priya@corp.local and reset its credentials.", "citations": ["ALR-000402"] }
  ],
  "validation": { "passed": true, "issues": [] },
  "generated_at": "2026-09-29T06:31:09Z"
}
```

`source` ∈ `cache` | `llm` | `template`. **This endpoint never returns an error because of the LLM** — on timeout, open breaker or failed validation it falls back to `template`.

---

## 8. Cohesion and split

### `GET /incidents/{id}/cohesion`

How confident the system is that these alerts are **one** incident.

```json
{
  "incident_id": "INC-7c1d04b9",
  "cohesion": "fragile",
  "reason": "single low-weight bridge splits the incident into two substantial halves",
  "bridge_edges": [
    { "alert_a": "ALR-000455", "alert_b": "ALR-000731",
      "entity_key": "ip:10.1.0.53", "weight": 3.11,
      "left_size": 22, "right_size": 15 }
  ],
  "split_preview": {
    "left":  { "alert_ids": ["ALR-000388","…"], "alerts": 22, "max_stage": 3,
               "headline": "Password spray → VPN access", "est_risk": 74.10, "est_priority": "P2" },
    "right": { "alert_ids": ["ALR-000731","…"], "alerts": 15, "max_stage": 6,
               "headline": "Lateral movement → exfiltration from fin-db-01", "est_risk": 91.30, "est_priority": "P1" }
  }
}
```

`cohesion` ∈ `solid` | `moderate` | `fragile`. `split_preview` is present only when `fragile`.

### `POST /incidents/{id}/split` 🔒

Materialises the two halves as separate incidents. Records the analyst's judgement rather than applying it silently.

```json
{ "bridge": { "alert_a": "ALR-000455", "alert_b": "ALR-000731" },
  "note": "Shared proxy IP only — unrelated activity" }
```

**201**
```json
{
  "run_id": "0192b8d5-…",
  "source_incident_id": "INC-7c1d04b9",
  "incidents": [
    { "incident_id": "INC-a1b2c3d4", "priority": "P2", "risk": 74.10, "alert_count": 22 },
    { "incident_id": "INC-e5f6a7b8", "priority": "P1", "risk": 91.30, "alert_count": 15 }
  ],
  "audit_seq": 1418
}
```

The split creates a **new run** rather than editing the old one, so the original stays immutable and its receipt stays valid. **409** `NOT_FRAGILE` if the named edge is not a bridge.

---

## 9. Counterfactuals

### `GET /incidents/{id}/counterfactuals`

The minimal changes that would flip this incident's priority. Computed on demand from the closed-form score; nothing stored.

Optional query `?what_if_criticality=dc01:4` previews a CMDB edit without persisting it — this is what the Risk tab's live slider calls.

```json
{
  "incident_id": "INC-3f9a1c2e",
  "current": {
    "risk": 98.92, "priority": "P1",
    "factors": { "C": 1.00, "S": 1.00, "A": 1.00, "Q": 0.93 },
    "thresholds": { "P1": 84.10, "P2": 61.04, "P3": 38.22 }
  },
  "counterfactuals": [
    { "kind": "asset", "label": "if fin-db-01 were not tagged financial",
      "risk": 61.04, "priority": "P2", "delta": -37.88, "closes_case": true },

    { "kind": "factor", "factor": "C", "label": "if the chain stopped at lateral movement",
      "value": 0.73, "risk": 88.70, "priority": "P1", "delta": -10.22, "closes_case": false },

    { "kind": "factor", "factor": "Q", "label": "if confidence dropped to 0.30",
      "value": 0.30, "risk": 83.50, "priority": "P2", "delta": -15.42, "closes_case": false },

    { "kind": "alert", "alert_id": "ALR-001102", "label": "remove ALR-001102",
      "risk": 76.21, "priority": "P2", "delta": -22.71, "closes_case": true },

    { "kind": "boundary", "factor": "A",
      "label": "to fall below P1, asset impact would need to be ≤ 0.42",
      "target_value": 0.42, "reachable": true },

    { "kind": "boundary", "factor": "S",
      "label": "severity alone cannot move this below P1",
      "target_value": null, "reachable": false }
  ]
}
```

`closes_case` is the field that matters operationally — it names the single piece of evidence holding a regulatory clock open.

`reachable: false` means that factor alone cannot reach the band edge even at its extreme. Report it honestly rather than clamping to 0 and printing a number that is not true.

---

## 10. Receipts

### `GET /runs/{id}/receipt`

```json
{
  "run_id": "0192a7c4-…",
  "dataset_id": "ds_20260929_s42",
  "scheme": "v1",
  "input_hash":  "sha256:4e07c8f1a9…",
  "config_hash": "sha256:b71e3a0c55…",
  "output_hash": "sha256:0c4a9d21fe…",
  "engine_version": "2.0.0",
  "attack_version": "19.0",
  "dialect": "sqlite",
  "computed_at": "2026-09-29T06:31:08Z",
  "config": {
    "link_window": "2h", "supernode_ratio": 0.05,
    "weights": { "C": 0.35, "S": 0.20, "A": 0.30, "Q": 0.15 },
    "capacity": { "p1_per_shift": 5, "p2_per_shift": 10 },
    "laundering_pass": true
  }
}
```

**The claim, scoped precisely:** two runs with the same `input_hash` and `config_hash` produce the same `output_hash` — on either dialect, on any machine. It proves the engine is a pure function of its inputs. **It does not prove the answer is correct**; that is what `/evaluations` and `/adversary` are for. State both halves.

`dialect` is informational only. A Postgres run and a SQLite run of the same input must produce **identical** hashes — the cross-dialect determinism test enforces it.

---

## 11. Adversary bench

Generates attackers that know how Prahari works, and measures how far they get.

### `POST /adversary/campaigns` 🔒

```http
POST /api/v1/adversary/campaigns
Idempotency-Key: 8c2f…

{
  "base_dataset": "ds_20260929_s42",
  "strategy": "supernode_laundering",
  "budgets": [0, 0.25, 0.5, 0.75, 1.0],
  "mitigated": false,
  "seed": 42
}
```

`strategy` ∈ `entity_rotation` | `temporal_dilation` | `supernode_laundering` | `noise_flood`.

**202** `Location: /api/v1/adversary/campaigns/camp_01J9…`
```json
{
  "campaign_id": "camp_01J9ABCD",
  "base_dataset": "ds_20260929_s42",
  "strategy": "supernode_laundering",
  "budgets": [0,0.25,0.5,0.75,1.0],
  "mitigated": false,
  "status": "queued",
  "created_at": "2026-09-29T07:02:00Z",
  "events_url": "/api/v1/adversary/campaigns/camp_01J9ABCD/events"
}
```

**422** `NO_GROUND_TRUTH` — a campaign needs a base dataset with planted truth, because the whole output is recall against that truth.

### `GET /adversary/campaigns/{id}`

```json
{
  "campaign_id": "camp_01J9ABCD",
  "base_dataset": "ds_20260929_s42",
  "strategy": "supernode_laundering",
  "mitigated": false,
  "status": "succeeded",
  "results": [
    { "budget": 0.00, "variant_dataset": "ds_adv_camp01J9_b000", "run_id": "…",
      "scenario_recall": 0.0, "pairwise_precision": 0.0, "pairwise_recall": 0.0,
      "incidents": 0, "detected": false, "top_rank": null },
    { "budget": 0.25, "…": "…" },
    { "budget": 0.50, "…": "…" },
    { "budget": 0.75, "…": "…" },
    { "budget": 1.00, "…": "…" }
  ],
  "duration_ms": 0
}
```

> All result values here are **zeroed placeholders**. They get filled by running the bench. Publishing an invented curve would defeat the entire purpose of building one.

### `GET /adversary/curve?base_dataset=…`

Plot-ready, everything the chart needs in one call.

```json
{
  "base_dataset": "ds_20260929_s42",
  "metric": "scenario_recall",
  "budgets": [0, 0.25, 0.5, 0.75, 1.0],
  "series": [
    { "strategy": "entity_rotation",      "mitigated": false, "values": [0,0,0,0,0],
      "crosses_floor_at": null },
    { "strategy": "temporal_dilation",    "mitigated": false, "values": [0,0,0,0,0],
      "crosses_floor_at": null },
    { "strategy": "supernode_laundering", "mitigated": false, "values": [0,0,0,0,0],
      "crosses_floor_at": null },
    { "strategy": "supernode_laundering", "mitigated": true,  "values": [0,0,0,0,0],
      "crosses_floor_at": null }
  ],
  "floor": 0.70,
  "floor_label": "acceptable detection floor"
}
```

`crosses_floor_at` is the interpolated budget where a series drops below `floor` — the annotation judges will read first. `null` means it never crosses within the tested range.

**Chart rule:** at most three strategies get their own colour (the categorical palette caps at three). A fourth goes in its own faceted panel rather than borrowing a fourth hue. Mitigated series draw as a dashed line in the **same** colour as their unmitigated counterpart, with the area between shaded — the gap is the improvement.

### `GET /adversary/campaigns/{id}/events` — SSE

`event` ∈ `budget.started`, `budget.finished`, `done`, `error`.

```
id: 12
event: budget.finished
data: {"campaign_id":"camp_01J9ABCD","budget":0.5,"scenario_recall":0.0,"detected":false}
```

---

## 12. Feedback and rules

### `POST /incidents/{id}/feedback`

```http
Idempotency-Key: 9d3a…

{
  "verdict": "false_positive",
  "note": "Authorised Qualys scan window",
  "suppress": { "rule_id": "NET-PORTSCAN", "entity_key": "ip:10.1.9.20",
                "expires_at": "2026-10-29T00:00:00Z" }
}
```

**201**
```json
{
  "feedback": { "feedback_id": 17, "incident_id": "INC-7c1d04b9", "run_id": "0192a7c4-…",
                "verdict": "false_positive", "note": "Authorised Qualys scan window",
                "user_id": "u_meow", "created_at": "2026-09-29T06:33:10Z" },
  "status": "false_positive",
  "rule_updates": [
    { "rule_id": "NET-PORTSCAN", "alpha": 2, "beta": 4,
      "precision_before": 0.40, "precision_after": 0.33 }
  ],
  "suppression": { "suppression_id": 3, "rule_id": "NET-PORTSCAN", "entity_key": "ip:10.1.9.20", "…": "…" },
  "rerun_recommended": true
}
```

α increments on `confirmed`, β on `false_positive`, **once per distinct rule** in the incident. The current run's scores do not change — the UI shows a **Re-run** button driven by `rerun_recommended`. This works identically for every alert source, which is the thing Microsoft's own triage agent does only for email.

`suppress` by an `analyst` ⇒ **403**. A duplicate `(rule, entity)` pair ⇒ **409** `ALREADY_EXISTS`.

### `GET /rules`

```json
{ "data": [
  { "rule_id": "NET-PORTSCAN", "rule_name": "Internal port scan", "source": "network",
    "technique_id": "T1046", "alpha": 2, "beta": 4, "precision": 0.33,
    "confirmed": 0, "false_positives": 1, "alerts_in_current_runs": 412 }
] }
```

---

## 13. Assets

### `GET /assets?min_criticality=7&data_class=pii`

```json
{ "data": [
  { "hostname": "fin-db-01", "role": "finance_database", "criticality": 9,
    "data_classes": ["pii","financial"], "owner": "finance-it",
    "updated_at": "2026-09-27T10:00:00Z" }
] }
```

### `PUT /assets/{hostname}` 🔒

```json
{ "role": "workstation", "criticality": 2, "data_classes": [], "owner": "interns" }
```

**200**/**201** → `Asset`. Hostname in the path must already be normalised (lowercase short name). **Takes effect on the next run** — which is exactly the live what-if demo: change criticality, re-run, watch the queue re-rank.

---

## 14. Compliance

### `GET /compliance/cases?state=open`

```json
{
  "server_time": "2026-09-29T07:02:00Z",
  "data": [{
    "case_id": "CASE-0001",
    "incident_id": "INC-3f9a1c2e",
    "dataset_id": "ds_20260929_s42",
    "priority": "P1",
    "headline": "Password spray → VPN access → lateral movement to dc01 → exfiltration from fin-db-01",
    "detected_at": "2026-09-29T06:31:07Z",
    "trigger": { "priority": "P1", "max_stage": 6, "assets": ["fin-db-01"], "data_classes": ["pii","financial"] },
    "tracks": [
      { "track": "certin", "authority": "CERT-In",
        "basis": "CERT-In Directions (28 Apr 2022): report within 6 hours of noticing",
        "deadline": "2026-09-29T12:31:07Z", "deadline_kind": "statutory",
        "status": "drafted", "overdue": false, "remaining_seconds": 19147,
        "submitted_at": null, "submitted_by": null, "reference": null },
      { "track": "dpdp_intimation", "authority": "Data Protection Board of India",
        "basis": "DPDP Rules 2025, Rule 7: intimate without delay (internal SLA 1 h)",
        "deadline": "2026-09-29T07:31:07Z", "deadline_kind": "internal_sla",
        "status": "drafted", "overdue": false, "remaining_seconds": 1747 },
      { "track": "dpdp_report", "authority": "Data Protection Board of India",
        "basis": "DPDP Rules 2025, Rule 7: detailed report within 72 hours",
        "deadline": "2026-10-02T06:31:07Z", "deadline_kind": "statutory",
        "status": "drafted", "overdue": false, "remaining_seconds": 257947 }
    ]
  }]
}
```

**Three tracks, not two.** The one-hour intimation SLA is the tightest obligation in the product; it was missing from the earlier design and from the mockup.

`remaining_seconds` is computed at `server_time`; the UI ticks from `deadline` and corrects drift against `server_time`. `state` ∈ `open` | `overdue` | `closed` | `all`.

### `GET /compliance/cases/{id}/drafts/{track}?format=json|markdown`

```json
{
  "case_id": "CASE-0001", "track": "certin",
  "generated_at": "2026-09-29T06:31:08Z",
  "evidence_hash": "sha256:4e07…",
  "disclaimer": "Auto-generated draft for review by the organisation. Not legal advice. Not submitted.",
  "fields": {
    "incident_type": "Unauthorised access to IT systems; data exfiltration",
    "occurred_at": "2026-09-29T03:32:11Z",
    "detected_at": "2026-09-29T06:31:07Z",
    "affected_systems": [
      { "hostname": "dc01", "role": "domain_controller", "ips": ["10.1.0.10"] },
      { "hostname": "fin-db-01", "role": "finance_database", "ips": ["10.2.0.21"] }
    ],
    "attack_vector": "Password spraying against VPN followed by use of a valid account",
    "techniques": ["T1110.003 Password Spraying","T1078 Valid Accounts","T1021.001 Remote Desktop Protocol","T1041 Exfiltration Over C2 Channel"],
    "indicators": { "external_ips": ["185.220.101.7"], "hashes": [], "accounts": ["priya@corp.local"] },
    "actions_taken": ["Incident triaged in Prahari","Account disable recommended","Source IP block recommended"],
    "contact": "SOC Lead, <organisation>"
  }
}
```

DPDP intimation fields: `description, nature, extent, timing, location, likely_impact`.
DPDP report fields: `facts, circumstances, reasons, mitigation[], findings, remedial_steps[], data_principal_notice`.

### `POST /compliance/cases/{id}/tracks/{track}/submission` 🔒

```json
{ "submitted_at": "2026-09-29T08:40:00Z", "reference": "CERTIN-2026-000123",
  "note": "Submitted by CISO via incident email" }
```

**Prahari never contacts a regulator.** This records who submitted, when, and the reference. **409** `ALREADY_SUBMITTED`.

### `GET /governance/retention`

```json
{
  "policy_days": 180,
  "basis": "CERT-In Directions: maintain ICT system logs for 180 days",
  "dialect": "postgres",
  "mechanism": "partition_drop",
  "next_run_at": "2026-09-30T00:00:00Z",
  "units": [
    { "table": "alerts", "name": "alerts_2026_09", "from": "2026-09-01T00:00:00Z",
      "to": "2026-10-01T00:00:00Z", "rows": 3000, "drop_after": "2027-03-30T00:00:00Z" },
    { "table": "alert_entities", "name": "alert_entities_2026_09", "from": "2026-09-01T00:00:00Z",
      "to": "2026-10-01T00:00:00Z", "rows": 11240, "drop_after": "2027-03-30T00:00:00Z" }
  ]
}
```

`alert_entities` appears here because it is partitioned on the same boundaries. Previously it was not, which orphaned entity rows forever and made this panel report a policy the database was not honouring.

`mechanism` is `partition_drop` on Postgres and `delete_by_timestamp` on SQLite.

---

## 15. Evaluations

### `POST /evaluations` 🔒

```json
{ "run_id": "0192a7c4-…", "analyst_model": { "seconds_per_alert": 30, "seconds_per_incident": 180 } }
```

**201**
```json
{
  "evaluation_id": "ev_01J8ZM0",
  "run_id": "0192a7c4-…",
  "dataset_id": "ds_20260929_s42",
  "analyst_model": { "seconds_per_alert": 30, "seconds_per_incident": 180 },
  "baseline": "analyst reads alerts in timestamp order at 30 s per alert",
  "metrics": {
    "compression_ratio": 0.0, "scenario_recall": 0.0,
    "pairwise_precision": 0.0, "pairwise_recall": 0.0, "mean_purity": 0.0,
    "precision_at_5": 0.0,
    "cohesion_accuracy": 0.0,
    "time_to_first_attack_baseline_s": 0, "time_to_first_attack_prahari_s": 0,
    "triage_time_reduction": 0.0, "noise_in_top10": 0.0, "correlate_ms": 0
  },
  "scenarios": [
    { "scenario": "A", "detected": false, "coverage": 0.0, "incident_id": null,
      "rank": null, "expected_priority": "P1", "actual_priority": null, "miss_reason": null },
    { "scenario": "E", "detected": false, "coverage": 0.0, "incident_id": null,
      "rank": null, "expected_priority": "P2", "actual_priority": null,
      "miss_reason": "gaps between steps exceed link_window (2h)" }
  ]
}
```

> Zeroed placeholders. Fill from measurement. **Always report the `baseline` alongside the reduction** — a number without its baseline is not evidence.

`cohesion_accuracy` is new: of the incidents flagged `fragile`, what fraction genuinely spanned two scenarios in the ground truth. It is how you defend the cohesion feature from "you just made that up".

**422** `NO_GROUND_TRUTH` for ingested datasets; `RUN_NOT_SUCCEEDED` for failed runs.

---

## 16. Audit

### `GET /audit?subject=INC-3f9a1c2e`

```json
{ "data": [
  { "seq": 1320, "ts": "2026-09-29T06:34:02Z", "actor": "u_meow",
    "action": "incident.updated", "subject": "INC-3f9a1c2e",
    "payload": { "status": { "from": "open", "to": "investigating" } },
    "prev_hash": "b7e1…", "hash": "0c4a…" }
] }
```

Actions: `dataset.created`, `ingest.batch`, `run.started`, `run.succeeded`, `run.failed`, `incident.updated`, `incident.split`, `feedback.created`, `suppression.created`, `suppression.deleted`, `asset.upserted`, `narrative.generated`, `case.opened`, `draft.generated`, `submission.recorded`, `campaign.created`, `campaign.finished`.

### `GET /audit/verify`

```json
{ "ok": true, "checked": 1320, "head_hash": "0c4a…", "broken_seq": null,
  "verified_at": "2026-09-29T06:40:00Z" }
```

Always **200**; a broken chain is `ok: false` with `broken_seq` naming the first bad row.

```
hash_n = hex(SHA-256( prev_hash || "|" || ts(RFC3339Nano) || "|" || actor || "|"
                      || action || "|" || subject || "|" || canonical_json(payload) ))
prev_hash_1 = "0" × 64
```

`canonical_json` = sorted keys, no insignificant whitespace. Go's `json.Marshal` on `map[string]any` already sorts keys. Implementations must match byte for byte across dialects.

---

## 17. System

### `GET /meta`

```json
{
  "version": "2.0.0",
  "commit": "a1b2c3d",
  "dialect": "sqlite",
  "attack_version": "19.0",
  "llm_enabled": false,
  "demo_mode": true,
  "engine": {
    "link_window": "2h", "supernode_ratio": 0.05,
    "laundering_pass": true,
    "weights": { "C": 0.35, "S": 0.20, "A": 0.30, "Q": 0.15 },
    "capacity": { "p1_per_shift": 5, "p2_per_shift": 10 },
    "band_mode": "calibrated"
  }
}
```

`band_mode` is `calibrated` (percentile, capacity-sized) or `fixed` (legacy 80/55/35). The UI shows which, because a priority means different things under each.

### Ops endpoints (no `/api/v1` prefix, not exposed through nginx)

| Path | Returns |
|---|---|
| `GET /healthz` | `200 {"status":"ok"}` if the process is alive |
| `GET /readyz` | `200` if DB reachable, migrations current, ATT&CK loaded; else `503` naming the failing check |
| `GET /metrics` | Prometheus text format |

---

## 18. Error catalogue

| HTTP | `code` | Meaning | UI behaviour |
|---|---|---|---|
| 400 | `VALIDATION_FAILED` | Body/query invalid; see `errors[]` | Inline field errors |
| 400 | `MALFORMED_JSON` | Body is not valid JSON | Toast |
| 400 | `INVALID_CURSOR` | Cursor tampered or expired | Reset list |
| 401 | `UNAUTHENTICATED` / `TOKEN_EXPIRED` | No or expired token | Go to login |
| 401 | `INVALID_CREDENTIALS` | Login failed | Form error |
| 403 | `FORBIDDEN` | Role not allowed | Hide or disable control |
| 404 | `NOT_FOUND` | Unknown id | Empty state |
| 409 | `RUN_IN_PROGRESS` | Run active; carries `active_run_id` | Attach to that run's SSE |
| 409 | `INVALID_STATE` | Illegal transition | Toast |
| 409 | `ALREADY_EXISTS` | Duplicate dataset or suppression | Toast with link |
| 409 | `ALREADY_SUBMITTED` | Track already submitted | Refresh case |
| 409 | `IDEMPOTENCY_KEY_REUSED` | Same key, different body | New key, retry |
| 409 | **`NOT_FRAGILE`** | Split requested on a non-bridge edge | Refresh cohesion |
| 412 | `PRECONDITION_FAILED` | ETag stale | Refetch, show diff |
| 413 | `PAYLOAD_TOO_LARGE` | Body >50 MB or line >1 MB | Split file |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Wrong `Content-Type` | Dev error |
| 422 | `DATASET_EMPTY` | Nothing to correlate | Prompt to simulate or ingest |
| 422 | `NO_GROUND_TRUTH` | Evaluation or campaign on an ingested dataset | Hide the action |
| 422 | `RUN_NOT_SUCCEEDED` | Evaluating a failed run | Toast |
| 422 | **`ADVERSARIAL_MIX`** | Run would mix adversarial and real alerts | Dev error |
| 428 | `PRECONDITION_REQUIRED` | `If-Match` missing | Dev error |
| 429 | `RATE_LIMITED` | Too many requests | Back off per `Retry-After` |
| 500 | `INTERNAL` | Unexpected; quote `request_id` | Generic error |
| 503 | `DEPENDENCY_UNAVAILABLE` | Database unreachable | Banner, auto-retry |

**The LLM being down is not an error code.** The narrative endpoint falls back to `source: "template"`.

---

## 19. Frontend integration

**Generate types, never hand-write them**

```bash
npx openapi-typescript ../backend/api/openapi.yaml -o src/api/schema.d.ts
```

```ts
import type { components } from "./schema";
export type IncidentSummary = components["schemas"]["IncidentSummary"];
export type Counterfactual  = components["schemas"]["Counterfactual"];
export type EvasionCurve    = components["schemas"]["EvasionCurve"];
```

**Fetch wrapper**

```ts
export class ApiError extends Error {
  constructor(public status: number, public code: string, public problem: unknown) { super(code); }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${getToken()}`, ...init.headers },
  });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, (body as any).code ?? "INTERNAL", body);
  return body as T;
}
```

**Run + SSE**

```ts
export function useRunEvents(runId?: string) {
  const qc = useQueryClient();
  useEffect(() => {
    if (!runId) return;
    const es = new EventSource(`/api/v1/runs/${runId}/events?access_token=${getToken()}`);
    es.addEventListener("stage", e => runProgress.getState().push(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("done",  () => { qc.invalidateQueries({ queryKey: ["incidents"] }); es.close(); });
    return () => es.close();
  }, [runId, qc]);
}
```

On `409 RUN_IN_PROGRESS`, read `active_run_id` from the problem body and subscribe to **that** run instead of failing.

**Query keys**

`["datasets"]` · `["alerts", datasetId, filters]` · `["runs", datasetId]` · `["incidents", datasetId, runId, filters]` · `["incident", id, runId]` · `["graph", id, runId]` · `["timeline", id, runId]` · `["narrative", id, runId]` · `["cohesion", id, runId]` · `["counterfactuals", id, runId, whatIf]` · `["receipt", runId]` · `["campaigns"]` · `["curve", datasetId]` · `["cases", state]` · `["assets"]` · `["rules"]` · `["evaluation", datasetId]`

Anything keyed by a concrete `runId` can use `staleTime: Infinity` — **incidents are immutable per run**. The exception is `counterfactuals`, which takes a `whatIf` key component because the criticality slider changes the result without a new run.

**Mocking before the backend exists** — MSW handlers returning the JSON examples in this document. Because the examples match `openapi.yaml`, swapping mocks for the real API is a config change.

---

## 20. Contract workflow

1. **Day 1:** freeze `alert.schema.json` and the first `openapi.yaml`. Everything downstream depends on it; if it moves at day nine you lose the night.
2. **Any change** starts as a PR editing `openapi.yaml` first, reviewed by the frontend and backend owners together.
3. **CI runs:**
   - `npx @redocly/cli lint openapi.yaml`
   - `openapi-typescript` → `tsc --noEmit` — the frontend compiles against the contract
   - Go handler tests validate real responses against the spec via `kin-openapi`
   - migration-parity check: `migrations/postgres` and `migrations/sqlite` must have identical version numbers
4. **Additive changes** merge anytime. **Breaking changes after Gate 2 are not allowed.**

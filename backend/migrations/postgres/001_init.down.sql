DROP TABLE IF EXISTS idempotency_keys, evaluations, evasion_results, evasion_campaigns, audit_log, audit_head,
  compliance_tracks, compliance_cases, dataset_cuts, feedback, suppressions, rule_stats, narratives,
  incident_state, incident_alerts, incidents, run_locks, runs, alert_entities, alerts, auth_events,
  datasets, assets, users CASCADE;
DROP FUNCTION IF EXISTS audit_log_append_only();

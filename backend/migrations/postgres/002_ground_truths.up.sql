-- Ground truth moves into the database so evaluation and the adversary bench
-- survive hosts whose local disk is wiped on restart. The API never returns
-- it and the engine never reads it; only the evaluator does.
CREATE TABLE ground_truths (
  dataset_id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  body       JSONB NOT NULL
);


-- Adds dataset/model versioning and antibiogram tables
BEGIN;
CREATE TABLE IF NOT EXISTS dataset_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind TEXT NOT NULL,
  version TEXT NOT NULL,
  checksum TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  meta JSONB
);
CREATE TABLE IF NOT EXISTS antibiogram (
  id BIGSERIAL PRIMARY KEY,
  drug TEXT NOT NULL,
  mic DOUBLE PRECISION NOT NULL,
  prob DOUBLE PRECISION NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source TEXT,
  UNIQUE (drug, mic, created_at)
);
COMMIT;

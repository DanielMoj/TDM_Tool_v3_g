-- db/migrations/001_init.sql
-- Basic schema for cases, priors, audit, reports, model_versions

CREATE TABLE IF NOT EXISTS model_versions (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  git_commit TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  patient_uid TEXT,
  drug TEXT NOT NULL,
  model_type TEXT NOT NULL,
  regimen JSONB NOT NULL,
  covariates JSONB,
  observations JSONB NOT NULL,
  backend TEXT NOT NULL,
  result_summary JSONB,
  draws_path TEXT,
  status TEXT DEFAULT 'done'
);

CREATE TABLE IF NOT EXISTS priors (
  id SERIAL PRIMARY KEY,
  drug TEXT UNIQUE NOT NULL,
  json JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ DEFAULT now(),
  user_name TEXT,
  role TEXT,
  event TEXT NOT NULL,
  details JSONB
);

CREATE TABLE IF NOT EXISTS reports (
  id BIGSERIAL PRIMARY KEY,
  case_id UUID REFERENCES cases(id),
  path TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

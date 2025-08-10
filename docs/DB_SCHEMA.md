# DB SCHEMA

Datenbank-Layout (optional) für Persistenz von Fällen, Priors, Reports und Audit-Logs. Migration: `db/migrations/001_init.sql`.

## Voraussetzungen
- Postgres 15+
- **Empfohlen**: `CREATE EXTENSION IF NOT EXISTS pgcrypto;` (für `gen_random_uuid()`)

## ER-Diagramm
```mermaid
erDiagram
  model_versions ||--o{ cases : "labels code baseline"
  cases ||--o{ reports : "has"
  priors ||--o{ cases : "by drug name"
  audit_log }}--|| cases : "ref via details.case_id (optional)"
```

## Tabellen

### `model_versions`
- `id` (serial PK)  
- `name` (text), `version` (text), `git_commit` (text), `created_at` (timestamptz)

### `cases`
- `id` (uuid PK, default `gen_random_uuid()`)
- `created_at`, `updated_at` (timestamptz)  
- `patient_uid` (text, optional/pseudonymisiert)  
- `drug` (text), `model_type` (text), `backend` (text)  
- `regimen` (jsonb), `covariates` (jsonb), `observations` (jsonb)  
- `result_summary` (jsonb), `draws_path` (text)  
- `status` (text) – z. B. `done`, `error`

**Beispiel-Insert**
```sql
INSERT INTO cases (patient_uid, drug, model_type, backend, regimen, observations)
VALUES ('PSEUDO-123', 'Meropenem', '2C', 'Laplace',
        '{"dose":1000,"tau":8,"tinf":0.5,"n_doses":6,"start_time":0}'::jsonb,
        '{"time":[1,7.5],"conc":[12.3,6.1]}'::jsonb);
```

### `priors`
- `id` (serial PK), `drug` (unique), `json` (jsonb), `created_at`, `updated_at`

### `audit_log`
- `id` (bigserial PK), `ts` (timestamptz)  
- `user_name` (text), `role` (text), `event` (text), `details` (jsonb)

### `reports`
- `id` (bigserial PK), `case_id` (uuid FK → cases.id), `path` (text), `created_at`

## Indizes (Vorschlag)
```sql
CREATE INDEX IF NOT EXISTS idx_cases_drug ON cases (drug);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases (status);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
```

## Zugriff aus R
- Verbindung: `DBI::dbConnect(RPostgres::Postgres(), dsn = Sys.getenv("PG_DSN"))`
- Audit-Schreiben: `db_write_audit(user, role, event, details)` (siehe `R/db.R`).

## Hinweise
- JSONB-Felder erlauben flexible Schemata, sollten aber via App **validiert** werden.  
- `draws_path` zeigt auf RDS/CSV im Filesystem; für große Draws besser externe Storage nutzen.

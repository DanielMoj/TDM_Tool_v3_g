
# Auth & Audit (hardened)

## Rollen & Policies
- Datei: `config/policies.yaml`
- Rollen: `admin`, `clinician`, `viewer`
- Prüfung: `policy_allow(role, action)`

## Session-Handling
- Datei: `config/session.yml` → `ttl_minutes`
- Login-Modal beim Start, TTL-Ablauf → erneuter Login
- Funktionen: `auth_set_user()`, `auth_logout()`, `auth_is_authenticated()`

## E-Sign (Basis)
- `esign_modal()` + `auth_esign_verify()`
- Für signaturpflichtige Aktionen: Passwort erneut abfragen; Signaturevent auditieren

## Audit
- CSV mit Hash-Kette: `audit_append_hashchain()`, Prüfung: `audit_verify_chain()`
- DB-Sink (optional): Tabelle `audit_log` (Migration `003_audit.sql`), Funktion `.aud_db_write()`
- Zentrales Logging: `audit_event(action, payload, session, require_reason)`
- App-Hooks: `fit_run`, `optimize_run`, `ehr_fetch`, `ehr_adopt`, `cfr_import`, `cfr_use`

## API-Auth (Plumber)
- Datei: `api/plumber_auth.R`
- Endpoint: `POST /auth/token` (username/password → Bearer JWT, 1h)
- Filter: `@filter bearerAuth` prüft `Authorization: Bearer <token>`
- Secret: ENV `TDMX_JWT_SECRET`

## Setup
```r
install.packages(c("yaml","sodium","digest","DBI","RPostgres","jose"))
# ENV: TDMX_JWT_SECRET, PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD
```

# AI_README

**Zweck:** Schneller Einstieg für KI-Agenten. Führe Tests aus, sammle Artefakte, schlage Fixes vor.

## Schnellstart
```r
# Abhängigkeiten
source("scripts/install_deps.R")

# deterministische Einstellungen (kurze Iterationen für CI)
options(tdmx_hmc=list(chains=2, iter_warmup=300, iter_sampling=300, adapt_delta=0.9, max_treedepth=11))
set.seed(123)

# Test-Suite
source("scripts/run_all_tests.R")  # Artefakte landen in ./artifacts
```

## Artefakte (für maschinelle Auswertung)
- `artifacts/test-results.xml` (JUnit)
- `artifacts/summary.json` (kompakte Übersicht je Test)
- `artifacts/console.log` (Logs/Stacktraces)
- `artifacts/coverage.html` (Coverage-Report, best effort)

## Umgebungsvariablen
- Postgres: `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`
- JWT: `TDMX_JWT_SECRET` (für `/auth/token` in Plumber)

## Wichtigste Ordner/Dateien
- `app.R` (Shiny-App)
- `R/` (PK/PD-Modelle, Backends, Optimierung, FHIR, Audit/Auth, ODE-Grid)
- `models/stan/` (Stan-Modelle inkl. nichtlinear)
- `models/jags/` (JAGS-Modelle inkl. nichtlinear, t/Mixture, BLQ)
- `api/` (Plumber-API, inkl. Auth-Filter)
- `docs/` (Architektur, Tests, diese Datei, u. a.)
- `scripts/` (Install/Test-Runner)
- `priors/` (Priors je Wirkstoff), `config/` (Ziele, LOINC, Risk-Modelle)

## Ergebnisformat
Bitte liefere Berichte in folgendem JSON-Format (siehe auch `docs/TEST_ARTIFACTS_SCHEMA.md`):

```json
{
  "summary": { "passed": 0, "failed": 0, "skipped": 0, "duration_sec": 0.0 },
  "failures": [ { "test":"file#name", "message":"...", "log_excerpt":"...", "suggested_fix":"<unified diff>", "area":"stan|jags|fhir|db|auth|opt|api|ui" } ],
  "warnings": [],
  "coverage": { "overall": "0%", "low_files": [] }
}
```

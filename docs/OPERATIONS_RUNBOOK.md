# OPERATIONS_RUNBOOK

## Start
- App: `shiny::runApp()` oder via Container
- API: `plumber::pr('api') |> pr_run(port=8000)`

## Healthchecks
- `/lis/antibiogram/list` (API), Login-Seite (App)

## Häufige Fehler
- Kein Stan/JAGS installiert → ADVI/Laplace-Fallback oder Pakete nachrüsten
- DB down → CFR-DB-UI skippt; Logs prüfen

## Logs & Audit
- `log/audit.csv` (Hash-Kette), DB-Tabelle `audit_log` (optional)

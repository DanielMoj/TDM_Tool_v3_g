# AI_HANDOFF

Diese Datei ist eine **präzise Übergabe** an eine nachfolgende KI/Entwicklerin.

## Ziel
Ein interaktives TDM-Tool (R/Shiny) mit Bayes-Inferenz, PTA/CFR, Diagnostik und Basiskonnektoren. **Nicht klinisch validiert.**

## Was fertig ist (Phase 3)
- Siehe **README** und **CHANGELOG**. Kernpunkte: 1C/2C/3C (+CRRT/MM/TMDD-Skeleton), Laplace/Stan/ADVI, BLQ (M3), PTA/CFR, PPC, Report.

## Wie starten
1. **Lokal**: `shiny::runApp()` (Pakete laut README installieren)  
2. **Docker**: `docker compose up --build -d` → Migration einspielen.  
3. **API**: `GET /healthz`, `POST /fit`, `POST /predict` (siehe **API.md**).

## Wichtigste Dateien
- `app.R` (UI/Server), `R/*.R` (Domain/Backends), `models/stan/*.stan`, `priors/*.json`, `config/*.json|yaml`, `api/plumber.R`, `report/report.Rmd`.

## Konfiguration
- `config/targets.json` (Ziele), `config/tissue.json` (Site), `priors/*.json` (Priors).  
- `.env`/`PG_DSN` für Postgres (optional).

## Testfall (Smoke Test)
- Drug: **Meropenem**, Modell: **2C**, Backend: **Laplace**, Fehler: **kombiniert**  
- Regimen: Dose 1000 mg, τ=8 h, tinf=0.5 h, n_doses=6, start=0  
- Obs: t=[1, 7.5], c=[12.3, 6.1]  
- MIC: 1.0 mg/L, Ziel: fT>MIC ≥ 0.5  
**Erwartet:** Fit läuft durch, Posterior-Summary angezeigt, PTA ~60–90% (Demo), Report-Button erzeugt PDF.

## Do/Don’t
- **Do**: Priors/Targets **vor** klinischer Nutzung ersetzen; Einheiten prüfen; PPC & Diagnostik beachten.  
- **Don’t**: ADVI-Posterior ohne MCMC-Diagnostik als „wahr“ interpretieren.

## Nächste Arbeiten (Phase 4, Auszug)
- Infusions-Optimizer, Pareto-Mehrziel, Heatmaps, Ressourcen-Constraints.

## Acceptance Criteria für Änderungen
- Läuft lokal & im Docker; **keine** Regressionen im Fit/PTA/PPC.  
- **docs/** aktualisiert (API/ARCHITECTURE/CHANGELOG).  
- Neue Modelle: Tests + klare Annahmen/Parameterbereiche.

## Kontaktpunkte im Code
- **run_fit()** (zentraler Eintritt).  
- **predict_conc_grid()** (PK-Forward).  
- **pta_for_regimen()** (PTA).  
- **reporting.R** (PDF).

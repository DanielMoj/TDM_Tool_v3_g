# TDMx Open Advanced (Phase 3)

Ein offenes **R/Shiny**-Framework für **Therapeutisches Drug Monitoring (TDM)** mit **Bayes-Inferenz**, simulierten **Konzentrations-Zeit-Profilen** und **PTA/CFR**-Auswertung. 
**Status:** Forschungs-/Demostand (nicht für klinische Entscheidungen validiert).

## Highlights (Stand Phase 5)
- **PK-Modelle:** 1C analytisch, 2C/3C via ODE, **CRRT** (zeitvariierende CL) für 2C/3C, **Michaelis–Menten (1C)**, **TMDD-QSS (1C, Skeleton)**.
- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).
- **Fehler-Modelle:** additiv, proportional, kombiniert; **t-Residuen**, **Mixture**; **BLQ (M3)** via LLOQ.
- **PTA & CFR:** fT>MIC, AUC24/MIC, Cmax/MIC; **Site-of-Infection**-Faktoren (Plasma/ELF/Bone/CSF).
- **Diagnostik:** PPC, R-hat/ESS (bei Stan), nächster optimaler Samplingzeitpunkt.
- **Reporting:** PDF Report (rmarkdown).
- **Infra:** Plumber-API, Docker/Compose, Postgres-Schema, Warm-Start/Cache, Audit-CSV.

> 💡 **Platzhalter:** Pop-Priors & Thresholds in `priors/*.json` und `config/targets.json` sind **Beispieldaten**. Vor klinischem Einsatz bitte durch validierte Quellen ersetzen.

## Quickstart (lokal)
```r
# 1) Dependencies (R ≥ 4.1):
install.packages(c(
  "shiny","bslib","ggplot2","dplyr","DT","jsonlite","glue","readr","tibble","lubridate",
  "deSolve","numDeriv","MASS","rmarkdown","promises","future","zoo","posterior","bayesplot","digest","matrixStats"
))
# Optional Backends
# install.packages(c("cmdstanr","rstan","rjags"))
# 2) Start
shiny::runApp()
```

## Quickstart (Docker Compose)
```bash
docker compose up --build -d
# DB-Migration einspielen (einmalig)
docker exec -i $(docker ps -qf name=_db_) psql -U tdmx -d tdmx < db/migrations/001_init.sql
```
- Shiny UI: http://localhost:3838  
- API (Plumber): http://localhost:8000

## Projektstruktur (Kurz)
```
app.R, R/, models/, priors/, report/, api/, db/, config/, audit/, docs/
```

## Doku
- **ARCHITECTURE:** docs/ARCHITECTURE.md  
- **DATAFLOW:** docs/DATAFLOW.md  
- **SETUP:** docs/SETUP.md  
- **DEPLOYMENT:** docs/DEPLOYMENT.md  
- **API:** docs/API.md  
- **PK-Modelle:** docs/MODELS_PK.md  
- **Priors-Schema:** docs/PRIORS_SCHEMA.md  
- **Targets & PTA/CFR:** docs/TARGETS_PTA_CFR.md  
- **Fehler/BLQ:** docs/ERROR_MODELS.md  
- **Diagnostik:** docs/DIAGNOSTICS.md  
- **Changelog:** docs/CHANGELOG.md  
- **Contributing:** docs/CONTRIBUTING.md

## Lizenz & Haftung
Siehe **LICENSE**. Keine Gewährleistung; nicht zur direkten klinischen Nutzung vorgesehen.

---
*Stand: 2025-08-08*

- **Datenintegration:** FHIR/LIS (LOINC, Units), Antibiogramm-CSV → PTA/CFR, API-Endpoints.

- **Optimierung:** Infusionsstrategien, Constraints, Pareto (PTA vs Risiko), Heatmaps, Auto-Vorschlag.

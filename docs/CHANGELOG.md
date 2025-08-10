# CHANGELOG

Alle Änderungen mit Datum (2025-08-08).

## v0.3 – Phase 3
- Pädiatrie/Neonatal: Maturationsfunktion & Prior-Shifts.
- Dialyse/CRRT: Zeitvariierende CL (2C_CRRT/3C_CRRT).
- Nichtlinear: Michaelis–Menten (1C), TMDD-QSS (1C, Skeleton).
- Joint-Kopplung: CL ↔ Kreatinin-Penalty.
- Gewebepenetration: Site-Faktoren (PTA/CFR).
- UI-Erweiterungen: Population, CRRT, Site, Kreatinin.

## v0.2 – Phase 2
- Diagnostik-Tab: PPC, R-hat/ESS (Stan).
- BLQ (M3): LLOQ + zensierte Likelihood (R & Stan).
- Robuste Fehler: t-Residuen, Mixture.
- Schnellpfad: Stan-ADVI + Warm-Start Cache.
- Design: Vorschlag nächster Samplingzeitpunkt.

## v0.1 – Phase 1
- Target-Bibliothek & MIC-Handling.
- PTA/CFR-Engine (fT>MIC, AUC24/MIC, Cmax/MIC).
- Dosing-Studio (PTA vs Dosis), Szenario-Vergleich.

## v0.0 – Phase 0
- Reporting-Helper (PDF).
- Plumber-API (healthz, fit, predict).
- Docker/Compose + Postgres-Schema.
- renv-Bootstrap; Observability-Notizen.

## v0.5 – Phase 5
- Datenintegration: FHIR-Fetch (Observation/LOINC), CSV-Ingest (TDM/MIC).
- Antibiogramm → MIC-Verteilung für PTA/CFR.
- API: neue Endpunkte `/ehr/fhir/observations`, `/lis/antibiogram/upload`.
- DB: `dataset_versions`, `antibiogram` (Migration 002).

## v0.4 – Phase 4
- Optimierung: Strategien, Constraints, Pareto (PTA vs Risiko), Heatmaps, Auto-Empfehlung.


## v0.6 – Hardening & Fixes (2025-08-09)
- **Risk-Model konfigurierbar:** `config/risk_models.json` (Vancomycin-AKI Logit), kein Hardcode mehr.
- **FHIR Pagination:** Mehrseiten-Fetch via `fhir_fetch_all_pages()` und `fhir_get_observations_all()`.
- **Security:** Passwort-Hashes via `sodium`; Fallback nur wenn `password_hash` fehlt.
- **Audit:** Hash-gekettete CSV-Logs (`audit_append_hashchain`), Verifikationsfunktion; DB-Migration `003_audit.sql`.
- **CRRT:** Modi CVVH/CVVHD/CVVHDF + Sieving-Faktor, Zeitplanfunktion.
- **Units-Checks:** Bolus (tinf=0) und kontinuierlich (tinf≥τ) erlaubt.
- **Bayes-Backend:** ADVI-Pfad (`fit_advi`) mit einfachem Cache (RDS).


## v0.7 – Stan/BLQ/Pathfinder (2025-08-09)
- **BLQ (M3) unter t-Residuen:** Stan nutzt jetzt `student_t_lcdf` statt Normal-Approximation.
- **Neuer Backend-Pfad:** *Stan-Pathfinder* (präzise & schnell) via cmdstanr `$pathfinder()`.
- **UI:** Auswahl *„Stan-Pathfinder (präzise & schnell)“* im Backend-Dropdown.


## v0.8 – CFR-Persistenz (Antibiogramm → DB) (2025-08-09)
- **R/db.R**: Postgres-Helper (Connect, Import, List/Get, Version-Record).
- **R/antibiogram.R**: DB-Bridge-Funktionen (Import, Liste, Fetch).
- **UI (Datenintegration)**: DB-Abschnitt (Liste, Übernehmen, CSV→DB-Import).
- **API**: `/lis/antibiogram/list`, `/lis/antibiogram/get`, `/lis/antibiogram/import`.
- **Docs**: `docs/ANTIBIOGRAM_DB.md`.


## v0.9 – HMC & Diagnostik (2025-08-09)
- **run_fit_stan** akzeptiert HMC-Controls (Chains, Iterationen, adapt_delta, max_treedepth).
- **Diagnose-Tab**: Zusammenfassung (R-hat/ESS), Divergenzen, Treedepth-Hits, Trace/Rank-Plots.
- **UI**: HMC/Stan-Einstellungen sichtbar, wenn Stan-Backends gewählt sind.


## v1.0 – Auth/Audit Hardening (2025-08-09)
- **Rollen & Policies:** `config/policies.yaml`, `policy_allow()`.
- **Session TTL:** `config/session.yml`, Login-Modal, Auto-Logout.
- **Audit:** zentral `audit_event()`, CSV-Hashkette + optional DB-Sink, App-Hooks an Schlüsselaktionen.
- **API-Auth:** `plumber_auth.R` mit `/auth/token` und Bearer-Filter (HMAC/JWT, `jose`).


## v1.1 – Nichtlineare Stan-Modelle (MM & TMDD-QSS) (2025-08-09)
- Neue Stan-Modelle: `pk_mm_onecpt_ode.stan`, `pk_tmdd_qss_onecpt_ode.stan`.
- Backend: `stan_file_for_model()`, `stan_data_list2()`; automatische Priors (Fallback) für neue Parameter.
- UI: Modell-Auswahl um **MM-1C** und **TMDD-QSS-1C** ergänzt.


## v1.2 – JAGS Nichtlinear (2025-08-09)
- **JAGS**: neue Modelle `pk_mm_onecpt_inf.jags` (MM-1C) und `pk_tmdd_qss_onecpt_inf.jags` (TMDD-QSS-1C).
- **run_fit_jags**: unterstützt jetzt **1C**, **MM-1C**, **TMDD-QSS-1C**, inkl. **BLQ** (dinterval) und add/prop/combined Fehler.


## v1.2 – JAGS Nichtlinear (2025-08-09)
- **JAGS**: neue Modelle `pk_mm_onecpt_inf.jags` (MM-1C) und `pk_tmdd_qss_onecpt_inf.jags` (TMDD-QSS-1C).
- **run_fit_jags**: unterstützt jetzt **1C**, **MM-1C**, **TMDD-QSS-1C**, inkl. **BLQ** (dinterval) und add/prop/combined Fehler.


## v1.2 – JAGS-Nichtlinear (Euler) (2025-08-09)
- Neue JAGS-Modelle: `pk_mm_onecpt_disc.jags`, `pk_tmdd_qss_onecpt_disc.jags` (diskrete Euler-Integration).
- Backend: `build_time_grid()` + erweitertes `run_fit_jags()` mit Modellrouting.
- Doku: `docs/MODELS_JAGS.md`.


## v1.3 – JAGS: t-Residuen, Mixture & adaptives dt (2025-08-09)
- **JAGS-Modelle** `pk_mm_onecpt_disc.jags`, `pk_tmdd_qss_onecpt_disc.jags` erweitert:
  - Fehler: additiv, proportional, kombiniert, **t-add**, **t-prop**, **Mixture** (zwei Normalverteilungen).
  - **BLQ** via `dinterval()` + **trunkierte** Verteilungen (kein CDF-Hack).
  - **Adaptives dt**: feine Schritte um Dosen & Messungen, gröber dazwischen (Euler).
- **R/ode_grid.R**: `build_time_grid_adaptive()` neu; Backend nutzt dieses Grid.
- **Backend (JAGS)**: Datenliste inkl. Priors/Hyperparameter, Mixture-Parameter, Mapping `idx`.


## v1.3.1 – JAGS robust & adaptive grid fixes (2025-08-09)
- **JAGS-Modelle** überarbeitet: sauberes BLQ-Handling via `dinterval`, t-Residuen & Mixture integriert.
- **Adaptive Euler-Integration** stabilisiert (`R/ode_grid.R` neu geschrieben).
- **Backend**: konsistente `stan_data_list2()`, repariertes `run_fit_stan()` & `run_fit_jags2()` Daten-Mapping.

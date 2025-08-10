# Projektphasen – Überblick & Status (Stand: 2025-08-09)

Dieses Dokument fasst die Phasen des TDMx-Advanced-Projekts zusammen, inkl. Deliverables, relevanter Dateien und aktuellem Status.

## Phase 1 – Basis & Architektur
**Ziele:** Shiny-App-Grundgerüst, PK-Basismodelle, Priors/Targets, Laplace-Fit, Reporting-Skelett.  
**Wichtigste Artefakte:**
- `app.R`, `R/pk_models.R`, `R/error_models.R`, `priors/*.json`, `config/targets.json`
- `report/report.Rmd`
**Status:** ✅ abgeschlossen (später erweitert).

## Phase 2 – Modelle & Inferenz (Stan/JAGS-Basis)
**Ziele:** Mehrkompartiment-Modelle (Stan), Residualfehler (add/prop/kombi), BLQ-Grundlage, Bayes-Backends (Stan/HMC, ADVI), Diagnostik-Basis.
**Wichtigste Artefakte:**
- `models/stan/pk_multicpt_ode.stan`, `R/backend_bayes.R`, `R/diagnostics.R`
**Status:** ✅ abgeschlossen; weiter ausgebaut in v0.7–v0.9.

## Phase 3 – UX & Reporting
**Ziele:** Dosing-Studio/Szenarien/Sensitivität (Basis), Reports, bessere UI.
**Wichtigste Artefakte:**
- `R/pta_cfr.R`, `R/reporting.R`, UI-Tabs in `app.R`
**Status:** ✅ abgeschlossen (Reports noch Demo-Charakter).

## Phase 4 – Optimierung
**Ziele:** PTA-Maximierung unter Constraints, Pareto-Front, Heatmaps; Risiko-Metriken (AKI-Proxy).  
**Wichtigste Artefakte:**
- `R/optimize_regimen.R`, UI-Tab „Optimierung“ in `app.R`, `docs/OPTIMIZATION.md`
**Status:** ✅ implementiert; **AKI-Parameter** konfigurierbar via `config/risk_models.json` (Kalibrierung offen).

## Phase 5 – Datenintegration
**Ziele:** FHIR/HL7-Anbindung (Pagination), Antibiogramm→DB (CFR-Persistenz), API-Layer.  
**Wichtigste Artefakte:**
- `R/fhir.R` (Pagination, Bundle-Merge), `R/antibiogram.R`, `R/db.R`
- `api/plumber_phase5.R`, `api/plumber_auth.R`
- `db/migrations/002_versioning.sql`
**Status:** ✅ implementiert; **MIC-Fetch/Subscriptions** offen; LOINC-Mapping exemplarisch.

## Phase 6 – Security/Compliance
**Ziele:** Rollen/Policies, Session-TTL, Audit-Hashkette (+DB), API-Token (JWT), E‑Sign-Grundlagen.  
**Wichtigste Artefakte:**
- `R/auth.R`, `config/policies.yaml`, `config/session.yml`, `config/users.yaml.example`
- `R/audit.R`, `db/migrations/003_audit.sql`
- `api/plumber_auth.R`, `docs/AUTH_AUDIT.md`
**Status:** ✅ Grundfunktionen implementiert; **MFA/e‑Sign-Pflicht/Policy-Enforcement** weiter schärfen.

## Phase 7 – Erweiterte PK/PD (Nichtlinearitäten)
**Ziele:** MM & TMDD (QSS) in Stan **und** JAGS, robuste Fehler (t, Mixture), BLQ korrekt; adaptives ODE-Grid.  
**Wichtigste Artefakte:**
- Stan: `models/stan/pk_mm_onecpt_ode.stan`, `models/stan/pk_tmdd_qss_onecpt_ode.stan`
- JAGS: `models/jags/pk_mm_onecpt_disc.jags`, `models/jags/pk_tmdd_qss_onecpt_disc.jags`
- Grid: `R/ode_grid.R`
**Status:** ✅ implementiert; 2C/3C-Varianten & t‑Mixture in Stan offen.

## Phase 8 – Tests & CI-Artefakte
**Ziele:** Unit-, Integrations- und E2E-Tests mit maschinenlesbaren Outputs.  
**Wichtigste Artefakte:**
- `tests/testthat/*`, `scripts/install_deps.R`, `scripts/run_all_tests.R`
- Artefakte: `artifacts/test-results.xml`, `artifacts/summary.json`, `artifacts/console.log`, `artifacts/coverage.html`
**Status:** ✅ Basis-Suite vorhanden; **Simulations-Truth für MM/TMDD** & **Snapshot-E2E** noch auszubauen; CI-Pipeline optional.

---

## Aktueller Gesamtstatus
- **Implementiert:** Phasen 1–8 (Basisumfang).  
- **Offen/Nächste Schritte:**  
  1. Stan: Mixture-Fehler (inkl. BLQ-M3) & t‑Mixture; 2C/3C für MM/TMDD.  
  2. FHIR: MIC-Fetch + Subscriptions; LOINC-Mapping erweitern.  
  3. Reporting: GxP-ready (signierbar, Änderungsverlauf).  
  4. Tests: Simulations‑Truth‑Suiten & Snapshot‑E2E; CI‑Pipeline.  
  5. CRRT in Stan-ODE integrieren und validieren.

## Verweise
- Änderungsverlauf: `docs/CHANGELOG.md`  
- Roadmap: `docs/ROADMAP.md`  
- Teststrategie: `docs/TEST_STRATEGY.md`  
- Bekannte Limitierungen: `docs/KNOWN_LIMITATIONS.md`


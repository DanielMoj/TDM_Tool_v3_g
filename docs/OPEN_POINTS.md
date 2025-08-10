# Offene Punkte & Status (Stand: 2025-08-09 11:29 UTC)

Legende: ✅ erledigt · 🟡 teilweise · 🔴 offen

## Zusammenfassung
- **Fertig (✅):** Antibiogramm/CFR (DB), API-Auth (JWT-Layer), HMC-Controls & Diagnostik-Basis
- **Teilweise (🟡):** Nichtlinearitäten (1C ok), BLQ/t/Mixture (Stan noch ausbaufähig), CRRT (R-Profil), Stan-Abdeckung, Variational/HMC (Warm-Start/Cache), JAGS (nur 1C), FHIR (ohne MIC/Subscriptions), Auth/Audit (ohne MFA/e-Sign-Pflicht), Diagnostik-UI (Basis), API (ohne Rate-Limits)
- **Offen (🔴):** Pädiatrie/Neonatal, Joint Modeling (PK+Cr), AKI-Kalibrierung, CI-Pumpenmodell, adaptive/parallel Optimierung, LOINC/Units-Validierung, Reporting (GxP), Tests/CI & Repro, Async Fits/Queue, UI-Mapping/Dialog, i18n/A11y

---

## PK/PD-Modelle & Methodik
- 🟡 **Nichtlinearitäten (MM/TMDD/QSS)**
  - **Status:** MM-1C & TMDD-QSS-1C in **Stan & JAGS** umgesetzt; UI-Switch vorhanden.
  - **Offen:** 2C/3C-Varianten; Validierung & Simulations-Truth-Tests.
  - **Akzeptanzkriterien:** Posterior-Recovery auf Simulationsdaten (RMSE der Kernparameter < 30% bei n≥2 Spiegeln).
  - **Referenzdateien:** `models/stan/pk_mm_onecpt_ode.stan`, `models/stan/pk_tmdd_qss_onecpt_ode.stan`, `models/jags/*disc.jags`, `R/nonlinear.R`

- 🟡 **BLQ/LLOQ & robuste Fehler**
  - **Status:** Stan: BLQ (M3) unter t-Residuen korrekt; JAGS: t & Mixture & BLQ vorhanden.
  - **Offen:** Stan-Mixture (2×Normal), t-Mixture, PPCs gezielt pro Fehler-Modell.
  - **Akzeptanzkriterien:** PPC-Coverage 80–95% in simulierten Szenarien; kein systematischer Bias bei BLQ>30%.
  - **Referenzdateien:** `models/stan/pk_multicpt_ode.stan`, `R/error_models.R`, `models/jags/*disc.jags`

- 🔴 **Pädiatrie/Neonatal**
  - **Offen:** Wirkstoffspezifische Priors/Validierung; Alters-/Gewichts-Kovariaten.
  - **Akzeptanzkriterien:** Vorerst Richtwerte je Wirkstoff dokumentiert + Tests mit Neonatal-Fall (kein Fit-Abbruch).

- 🔴 **Joint Modeling (PK + Kreatinin)**
  - **Offen:** Gemeinsames Stan-Modell (PK + eGFR/Cr-Zeitreihe) statt Penalty.
  - **Akzeptanzkriterien:** Simulations-Truth: gemeinsame Schätzung reduziert Varianz von CL vs. PK-only (≥10%).

## CRRT/Dialyse
- 🟡 **CRRT**
  - **Status:** Modi (CVVH/CVVHD/CVVHDF), Sieving, Zeitplan in R implementiert.
  - **Offen:** Integration als zeitvariable CL im Stan-ODE; Filter-/Membran-Parameter; Validierung.
  - **Akzeptanzkriterien:** Stan-Simulation reproduziert R-Profil (MAE < 10% der AUC).

## Inferenz/Backends
- 🟡 **Stan-Abdeckung**
  - **Status:** Lineares Multi-Cpt; MM-1C; TMDD-QSS-1C; HMC/ADVI/Pathfinder.
  - **Offen:** Mixture-Fehler in Stan; BLQ-M3 unter Mixture; 2C/3C nichtlinear; Tests & extra Diagnoseplots.
  - **Akzeptanzkriterien:** Alle Fehlermodelle stanbar ohne Divergenzen bei Test-Fall (adapt_delta 0.95).

- 🟡 **Variational/HMC**
  - **Status:** HMC-Controls, Diagnostik-Tab; Pathfinder verfügbar.
  - **Offen:** Warm-Starts/Cache auch für HMC; parallele Chains-Tuning.
  - **Akzeptanzkriterien:** Warm-Start reduziert HMC-Gesamtzeit um ≥25% bei Wiederhol-Fit.

- 🟡 **JAGS**
  - **Status:** 1C nichtlinear (MM/TMDD) inkl. t & Mixture; adaptives Euler-Grid.
  - **Offen:** Mehrkompartiment (2C/3C) & Kovariaten.
  - **Akzeptanzkriterien:** 2C-JAGS-Fit stabil auf Simulationsdaten (ESS_bulk>200 für CL, Vc).

## Optimierung (Phase 4)
- 🔴 **AKI-Risiko**
  - **Offen:** Klinische Kalibrierung der Logit-Parameter je Klinik.
  - **Akzeptanzkriterien:** ROC-AUC ≥0.7 auf lokalem Datensatz oder dokumentierte Ableitung aus Literatur.

- 🔴 **Kontinuierliche Infusion (CI)**
  - **Offen:** Explizite Pumpen-/Loading-Modelle; Compliance-Constraints.
  - **Akzeptanzkriterien:** Vorschlag enthält optionalen Loading-Bolus; PTA-Vergleich CI vs. verlängert.

- 🔴 **Suche/Performance**
  - **Offen:** Adaptives Refinement, Parallelisierung, Memoisierung.
  - **Akzeptanzkriterien:** Laufzeit-Reduktion um ≥30% bei gleichbleibender PTA-Qualität.

## Datenintegration (Phase 5)
- 🟡 **FHIR**
  - **Status:** Pagination & Merge über mehrere Seiten.
  - **Offen:** MIC-Fetch & Mapping; Subscriptions/Webhooks; Retry/Backoff.
  - **Akzeptanzkriterien:** Mind. ein MIC-Feld per LOINC gemappt; 24h-Subscription-Demo mit Auto-Import.

- ✅ **Antibiogramm/CFR (DB)**
  - **Status:** Persistenz, UI, API einsatzbereit.
  - **Akzeptanzkriterien:** Vorhanden (bestehend).

- 🔴 **LOINC/Units**
  - **Offen:** Standort-Mapping & Validierung.
  - **Akzeptanzkriterien:** Validierte Mapping-Tabelle; 0 „unknown“-Felder im E2E-Mapping-Test.

## Security, Audit, Compliance
- 🟡 **Auth**
  - **Status:** Rollen/Policies; Session-TTL; gehashte Passwörter (sodium).
  - **Offen:** MFA; strenger Policy-Enforcer; Ablösung YAML-Userstore.
  - **Akzeptanzkriterien:** MFA-Flow aktiv; Userstore in DB mit Hash + Rotation.

- 🟡 **Audit**
  - **Status:** Hash-Kette; zentraler Logger (CSV + optional DB); API-JWT.
  - **Offen:** Verpflichtende e-Sign bei heiklen Aktionen; vollständige Event-Abdeckung.
  - **Akzeptanzkriterien:** e-Sign-Pflicht beim Report-Export & Regime-Override; Audit-Kette verifizierbar (OK).

- 🔴 **Reporting**
  - **Offen:** Signierbare PDFs, Änderungsverlauf, Klinik-Blöcke.
  - **Akzeptanzkriterien:** PDF enthält Signatur-Metadaten + Audit-Hash; Report-Template parametrisiert.

## Diagnostik, Tests & Repro
- 🟡 **Diagnostik-UI**
  - **Status:** R-hat/ESS, Divergenzen, Treedepth, Trace/Rank.
  - **Offen:** Energy/BFMI; Divergenz-Heatmaps; BLQ-spezifische PPCs.
  - **Akzeptanzkriterien:** mind. 2 neue Plot-Typen + PPC-Kacheln pro Zielmetrik.

- 🔴 **Tests**
  - **Offen:** Simulations-Truth (MM/TMDD), Snapshot-E2E, CI-Pipeline.
  - **Akzeptanzkriterien:** Alle Tests grün in CI; JUnit & summary.json als Artefakte; Coverage ≥60%.

- 🔴 **Repro/Builds**
  - **Offen:** `renv`/Lockfile; Release-Bundles (Model+Priors+Checksums); deterministische Seeds.
  - **Akzeptanzkriterien:** Reproduzierbarer Build mit fixem Lockfile + Bundle-Artefakt.

## API/Deploy/UX
- 🟡 **API**
  - **Status:** Auth-Layer (JWT), Antibiogramm-Endpoints.
  - **Offen:** Rate-Limits/Throttling; `/v1`-Namespaces.
  - **Akzeptanzkriterien:** 429-Handling; versionierte Pfade aktiv.

- 🔴 **Asynchrone Fits/Queue**
  - **Offen:** `future`/`targets`, Job-Queue, Result-Cache.
  - **Akzeptanzkriterien:** Fits laufen async; UI pollt Ergebnisse; Cache-Trefferquote sichtbar.

- 🔴 **UI-Adoption Heuristik**
  - **Offen:** Mapping-Dialog oder Schnittstellenvertrag statt Heuristik.
  - **Akzeptanzkriterien:** 0 Heuristik-Treffer nötig im E2E-Test auf Demo-Daten.

- 🔴 **i18n/A11y**
  - **Offen:** Mehrsprachen, Shortcuts, Units-Sets.
  - **Akzeptanzkriterien:** Umschaltbares Language-Pack; Tastaturkürzel dokumentiert.

---

## Verweise
- Phasenübersicht: `docs/PROJECT_PHASES.md`
- Teststrategie: `docs/TEST_STRATEGY.md`
- KI-Onboarding: `docs/AI_README.md`, `docs/LLM_ONBOARDING.md`

# PLACEHOLDERS_AUDIT_v2
_Timestamp: 2025-08-09 09:50 UTC_

## Zusammenfassung pro Datei
- `README.md` — **8**
- `README_PHASE0.md` — **6**
- `config/risk_models.json` — **2**
- `config/targets.json` — **3**
- `config/users.yaml` — **1**
- `db/migrations/001_init.sql` — **2**
- `db/migrations/002_versioning.sql` — **3**
- `db/migrations/003_audit.sql` — **2**
- `docs/AI_HANDOFF.md` — **4**
- `docs/API.md` — **2**
- `docs/ARCHITECTURE.md` — **13**
- `docs/CHANGELOG.md` — **16**
- `docs/CONFIGURATION.md` — **12**
- `docs/CONTRIBUTING.md` — **1**
- `docs/DATAFLOW.md` — **9**
- `docs/DB_SCHEMA.md` — **7**
- `docs/DEPLOYMENT.md` — **2**
- `docs/DIAGNOSTICS.md` — **3**
- `docs/EHR_LIS.md` — **3**
- `docs/ERROR_MODELS.md` — **11**
- `docs/GLOSSARY.md` — **8**
- `docs/KNOWN_LIMITATIONS.md` — **7**
- `docs/MODELS_PK.md` — **8**
- `docs/OPTIMIZATION.md` — **1**
- `docs/PERFORMANCE.md` — **7**
- `docs/PLACEHOLDERS_AUDIT.md` — **337**
- `docs/PLACEHOLDERS_AUDIT_SUMMARY.json` — **1**
- `docs/PRIORS_SCHEMA.md` — **1**
- `docs/REPORTS.md` — **2**
- `docs/ROADMAP.md` — **6**
- `docs/SECURITY.md` — **7**
- `docs/SETUP.md` — **2**
- `docs/TARGETS_PTA_CFR.md` — **4**
- `docs/TROUBLESHOOTING.md` — **6**
- `models/stan/pk_multicpt_ode.stan` — **13**

---
## Details
### README.md
- Zeile 7: `- **PK-Modelle:** 1C analytisch, 2C/3C via ODE, **CRRT** (zeitvariierende CL) für 2C/3C, **Michaelis–Menten (1C)**, **TMDD-QSS (1C, Skeleton)**.`
- Zeile 8: `- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).`
- Zeile 9: `- **Fehler-Modelle:** additiv, proportional, kombiniert; **t-Residuen**, **Mixture**; **BLQ (M3)** via LLOQ.`
- Zeile 13: `- **Infra:** Plumber-API, Docker/Compose, Postgres-Schema, Warm-Start/Cache, Audit-CSV.`
- Zeile 15: `> 💡 **Platzhalter:** Pop-Priors & Thresholds in `priors/*.json` und `config/targets.json` sind **Beispieldaten**. Vor klinischem Einsatz bitte durch validierte Quellen ersetzen.`
- Zeile 41: `app.R, R/, models/, priors/, report/, api/, db/, config/, audit/, docs/`
- Zeile 53: `- **Fehler/BLQ:** docs/ERROR_MODELS.md`
- Zeile 64: `- **Datenintegration:** FHIR/LIS (LOINC, Units), Antibiogramm-CSV → PTA/CFR, API-Endpoints.`

### README_PHASE0.md
- Zeile 10: `- **.env.example** with `PG_DSN` environment variable.`
- Zeile 33: `- BLQ (M3) via LLOQ-Checkbox, Likelihood-Anpassung (Laplace & Stan)`
- Zeile 34: `- Robuste Fehler: t-Residuen & Normal-Mixture`
- Zeile 35: `- Schnellpfad: Stan-ADVI + Warm-Start Cache (digest, RDS)`
- Zeile 41: `- Dialyse/CRRT: Zeitvariierende CL via Schedule (start:dauer:effluent:S), 2C/3C_CRRT`
- Zeile 42: `- Nichtlinearitäten: Michaelis-Menten (1C) + TMDD-QSS Skeleton (1C)`

### config/risk_models.json
- Zeile 2: `"vanco_aki_logit": {`
- Zeile 5: `"note": "Default demo parameters. Replace with site-calibrated coefficients."`

### config/targets.json
- Zeile 6: `"notes": "Platzhalter; fT>MIC \u226550%"`
- Zeile 12: `"notes": "Platzhalter; 400\u2013600 angestrebt"`
- Zeile 17: `"notes": "Platzhalter; Ziel \u22658"`

### config/users.yaml
- Zeile 1: `# DEMO! Nicht für Produktion.`

### db/migrations/001_init.sql
- Zeile 2: `-- Basic schema for cases, priors, audit, reports, model_versions`
- Zeile 36: `CREATE TABLE IF NOT EXISTS audit_log (`

### db/migrations/002_versioning.sql
- Zeile 2: `-- Adds dataset/model versioning and antibiogram tables`
- Zeile 4: `CREATE TABLE IF NOT EXISTS dataset_versions (`
- Zeile 12: `CREATE TABLE IF NOT EXISTS antibiogram (`

### db/migrations/003_audit.sql
- Zeile 3: `CREATE TABLE IF NOT EXISTS audit_log (`
- Zeile 12: `CREATE INDEX IF NOT EXISTS audit_hash_idx ON audit_log(hash);`

### docs/AI_HANDOFF.md
- Zeile 9: `- Siehe **README** und **CHANGELOG**. Kernpunkte: 1C/2C/3C (+CRRT/MM/TMDD-Skeleton), Laplace/Stan/ADVI, BLQ (M3), PTA/CFR, PPC, Report.`
- Zeile 24: `- Drug: **Meropenem**, Modell: **2C**, Backend: **Laplace**, Fehler: **kombiniert**`
- Zeile 28: `**Erwartet:** Fit läuft durch, Posterior-Summary angezeigt, PTA ~60–90% (Demo), Report-Button erzeugt PDF.`
- Zeile 32: `- **Don’t**: ADVI-Posterior ohne MCMC-Diagnostik als „wahr“ interpretieren.`

### docs/API.md
- Zeile 21: `"backend": "Laplace",`
- Zeile 71: `- **Timeouts**: Lange HMC-Läufe vermeiden, ggf. ADVI/Laplace nutzen.`

### docs/ARCHITECTURE.md
- Zeile 7: `- **Application/Controller:** server-Logik in `app.R` orchestriert Inputs → Priors → Inferenz → Outputs → Audit.`
- Zeile 8: `- **Domain (PK/Fehler/Kovariaten):** `R/pk_models.R`, `R/error_models.R`, `R/units_checks.R`, `R/pediatric.R`, `R/crrt.R`, `R/nonlinear.R`, `R/tissue.R`.`
- Zeile 10: `- **Data Access & Config:** `R/prior_db.R`, `config/*.json|yaml`, `R/db.R` (optional Postgres), `audit/audit_log.csv`.`
- Zeile 20: `pediatric.R      crrt.R         nonlinear.R    tissue.R`
- Zeile 21: `joint.R          prior_db.R     audit.R        auth.R   reporting.R  db.R`
- Zeile 27: `config/targets.json  config/tissue.json  config/users.yaml`
- Zeile 33: `- **pk_models.R:** 1C analytisch; 2C/3C (ODE); *TVCL* für CRRT; Hooks für **MM** & **TMDD**.`
- Zeile 34: `- **error_models.R:** σ-Funktionen, **t-Residuen**, **Mixture**, **BLQ (M3)**-Likelihood.`
- Zeile 35: `- **backend_bayes.R:** Laplace/MAP; Stan (HMC) & **Stan-ADVI**; JAGS-1C; Diagnostics; Warm-Start Cache.`
- Zeile 39: `- **crrt.R:** Parser + CL(t)-Beitrag aus Effluent/Sieving.`
- Zeile 40: `- **nonlinear.R:** **MM (1C)** & **TMDD-QSS** (1C, Skeleton).`
- Zeile 45: `- **db.R:** Optionale Postgres-DAO (Audit etc.).`
- Zeile 66: `Backend->>Backend: MAP/HMC/ADVI (BLQ, Fehler)`

### docs/CHANGELOG.md
- Zeile 7: `- Dialyse/CRRT: Zeitvariierende CL (2C_CRRT/3C_CRRT).`
- Zeile 8: `- Nichtlinear: Michaelis–Menten (1C), TMDD-QSS (1C, Skeleton).`
- Zeile 11: `- UI-Erweiterungen: Population, CRRT, Site, Kreatinin.`
- Zeile 15: `- BLQ (M3): LLOQ + zensierte Likelihood (R & Stan).`
- Zeile 16: `- Robuste Fehler: t-Residuen, Mixture.`
- Zeile 17: `- Schnellpfad: Stan-ADVI + Warm-Start Cache.`
- Zeile 32: `- Datenintegration: FHIR-Fetch (Observation/LOINC), CSV-Ingest (TDM/MIC).`
- Zeile 33: `- Antibiogramm → MIC-Verteilung für PTA/CFR.`
- Zeile 34: `- API: neue Endpunkte `/ehr/fhir/observations`, `/lis/antibiogram/upload`.`
- Zeile 35: `- DB: `dataset_versions`, `antibiogram` (Migration 002).`
- Zeile 42: `- **Risk-Model konfigurierbar:** `config/risk_models.json` (Vancomycin-AKI Logit), kein Hardcode mehr.`
- Zeile 43: `- **FHIR Pagination:** Mehrseiten-Fetch via `fhir_fetch_all_pages()` und `fhir_get_observations_all()`.`
- Zeile 44: `- **Security:** Passwort-Hashes via `sodium`; Fallback nur wenn `password_hash` fehlt.`
- Zeile 45: `- **Audit:** Hash-gekettete CSV-Logs (`audit_append_hashchain`), Verifikationsfunktion; DB-Migration `003_audit.sql`.`
- Zeile 46: `- **CRRT:** Modi CVVH/CVVHD/CVVHDF + Sieving-Faktor, Zeitplanfunktion.`
- Zeile 48: `- **Bayes-Backend:** ADVI-Pfad (`fit_advi`) mit einfachem Cache (RDS).`

### docs/CONFIGURATION.md
- Zeile 7: `2. **Konfig-Dateien** in `config/` (`targets.json`, `tissue.json`, `users.yaml`)`
- Zeile 12: `- `PG_DSN` – Postgres-DSN (optional). Beispiel:`
- Zeile 15: `- `TDMX_AUDIT_PATH` – Pfad für Audit CSV (optional). Default: `audit/audit_log.csv`.`
- Zeile 20: `Beispiel (Platzhalter):`
- Zeile 23: `"Meropenem": {"metric": "fT>MIC", "threshold": 0.5, "window": "tau", "notes": "Demo"},`
- Zeile 28: `- Mapping per Drug-Name oder Heuristik (Klassenregex).`
- Zeile 40: `## `config/users.yaml` (Demo-Auth)`
- Zeile 41: `- Klartext-Benutzer nur für **Demo**. Für Produktion: `shinymanager`/SSO + Passwort-Hashes.`
- Zeile 49: `- `options(crrt_schedule_df = parse_crrt_schedule(...))` – CRRT-Profil.`
- Zeile 52: `- **Backend**: Laplace / Stan / Stan-ADVI / JAGS`
- Zeile 53: `- **Residuen**: additiv / proportional / kombiniert / t-* / mixture`
- Zeile 54: `- **BLQ**: LLOQ + Checkbox „≤ LLOQ ist BLQ“`

### docs/CONTRIBUTING.md
- Zeile 26: `- Beispiel-/synthetische Daten verwenden.`

### docs/DATAFLOW.md
- Zeile 10: `C --> D[Backend: Laplace | Stan(HMC) | Stan-ADVI | JAGS]`
- Zeile 16: `A --> J[Audit: fit_start/fit_done]`
- Zeile 19: `**BLQ:** LLOQ/Flags → Likelihood (M3) in R & Stan.`
- Zeile 32: `**AUC24:** Aus AUC über τ auf 24h skaliert (vereinfachend).`
- Zeile 40: `- **R-hat/ESS:** nur bei Stan-HMC; ADVI/Laplace liefern keine MCMC-Diagnostik.`
- Zeile 53: `## Fehlerbehandlung & Fallbacks`
- Zeile 55: `- **Stan/JAGS** nicht vorhanden → Fallback auf **Laplace/ADVI**.`
- Zeile 59: `- **Laplace**: Subsekunden bis wenige Sekunden.`
- Zeile 60: `- **Stan-ADVI**: schnell, gute Voransichten, aber ohne MCMC-Diagnostik.`

### docs/DB_SCHEMA.md
- Zeile 3: `Datenbank-Layout (optional) für Persistenz von Fällen, Priors, Reports und Audit-Logs. Migration: `db/migrations/001_init.sql`.`
- Zeile 15: `audit_log }}--|| cases : "ref via details.case_id (optional)"`
- Zeile 33: `**Beispiel-Insert**`
- Zeile 36: `VALUES ('PSEUDO-123', 'Meropenem', '2C', 'Laplace',`
- Zeile 44: `### `audit_log``
- Zeile 55: `CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);`
- Zeile 60: `- Audit-Schreiben: `db_write_audit(user, role, event, details)` (siehe `R/db.R`).`

### docs/DEPLOYMENT.md
- Zeile 19: `- `.env.example` vorhanden (lokaler Betrieb ohne Compose).`
- Zeile 33: `- **Demo-Auth** (`config/users.yaml`) ist nicht produktionsreif.`

### docs/DIAGNOSTICS.md
- Zeile 13: `## ADVI/Laplace`
- Zeile 14: `- **Keine** MCMC-Diagnostik (approx.). PPC prüft Plausibilität der Vorhersagen.`
- Zeile 18: `- PPC stark off → Fehlermodell prüfen (t/Mixture), Kovariaten (CRCL, Gewicht), Datenqualität (Einheiten/Zeiten).`

### docs/EHR_LIS.md
- Zeile 3: `- UI-Tab „Datenintegration“ mit FHIR-Fetch und CSV-Upload (Antibiogramm).`
- Zeile 4: `- Module: `R/fhir.R`, `R/loinc.R`, `R/antibiogram.R`, `R/lis_ingest.R`.`
- Zeile 6: `- Konfig: `config/loinc_map.json`, `config/fhir.json.example`.`

### docs/ERROR_MODELS.md
- Zeile 1: `# FEHLERMODELLE & BLQ`
- Zeile 10: `- **Mixture**: Mischung aus N(σ) und N(σ·scale), Gewicht w (robust gegen heavy tails).`
- Zeile 12: `## BLQ / M3`
- Zeile 13: `- **<LLOQ**-Werte werden als **zensiert** modelliert:`
- Zeile 14: `- Likelihood nutzt **CDF**: `P(Y < LLOQ)` statt Dichte in diesem Punkt.`
- Zeile 18: `- R: `make_sigma_fun()`, `loglik_residuals_vec()` (inkl. BLQ & Mixture).`
- Zeile 19: `- Stan: `error_model`-Codes (1=add, 2=prop, 3=comb, 4=t-add, 5=t-prop, 6=mixture).`
- Zeile 23: `- **t-Residuen/Mixture**: Ausreißer/Heavy Tails.`
- Zeile 24: `- **BLQ aktivieren**, wenn Messwerte ≤ LLOQ vorliegen.`
- Zeile 27: `- Mixture-Parameter (w, scale) sind heuristisch (Demo).`
- Zeile 28: `- t-Residuen teilen df (ν) global; je nach Drug anpassbar.`

### docs/GLOSSARY.md
- Zeile 7: `- **BLQ** – Below the Lower Limit of Quantification (<LLOQ).`
- Zeile 16: `- **Kappa (κ)** – Skalenfaktor für CRRT-Beitrag zur CL.`
- Zeile 17: `- **LLOQ** – Lower Limit of Quantification.`
- Zeile 18: `- **MAP** – Maximum a Posteriori (Laplace-Approximation).`
- Zeile 20: `- **MM** – Michaelis–Menten (nichtlineare Elimination).`
- Zeile 26: `- **QSS** – Quasi-Steady State (TMDD-Näherung).`
- Zeile 27: `- **Stan-ADVI** – Automatic Differentiation Variational Inference.`
- Zeile 29: `- **TMDD** – Target-Mediated Drug Disposition.`

### docs/KNOWN_LIMITATIONS.md
- Zeile 6: `- **Priors & Targets** sind **Platzhalter** (Demo) → nicht validiert für Klinik.`
- Zeile 7: `- **CRRT-Modell** vereinfacht (CL = Baseline + κ·Effluent·S).`
- Zeile 8: `- **TMDD** nur als **QSS-Skeleton**; keine validierte TMDD-Schätzung.`
- Zeile 13: `- **Stan** deckt **TVCL/MM/TMDD** aktuell **nicht** ab (Laplace/ADVI only).`
- Zeile 14: `- **Mixture/t-Residuen** Parameter sind heuristisch voreingestellt.`
- Zeile 19: `- **Auth** ist Demo (Klartext); **keine** SSO/e-Sign/eAudit.`
- Zeile 20: `- **Audit** (CSV) ist nicht kryptografisch gesichert.`

### docs/MODELS_PK.md
- Zeile 12: `## Zeitvariierende Clearance (CRRT)`
- Zeile 13: `### 2C_CRRT / 3C_CRRT`
- Zeile 19: `### Michaelis–Menten (MM, 1C)`
- Zeile 23: `### TMDD-QSS (Skeleton, 1C)`
- Zeile 25: `- Parameter: **Kon, Koff, Rtot, Kint**, **CL**, **Vc** (vereinfachend).`
- Zeile 33: `- **Stan (HMC)**: 1C/2C/3C ODE (ohne TVCL/MM/TMDD).`
- Zeile 34: `- **Laplace/ADVI**: alle o. g. Pfade (demonstrativ); bei MM/TMDD/CRRT bevorzugt.`
- Zeile 35: `- **JAGS**: 1C (Demo).`

### docs/OPTIMIZATION.md
- Zeile 8: `- `compute_pta_risk` (PTA + Risiko: `Cmax>limit` / `AUC24>limit` / `Vanco_AKI` Platzhalter)`

### docs/PERFORMANCE.md
- Zeile 6: `- **Laplace/MAP**: sehr schnell; gut für Routine/Exploration.`
- Zeile 7: `- **Stan-ADVI**: schnell (variational); keine MCMC-Diagnostik.`
- Zeile 9: `- **JAGS**: 1C-Demo; nicht empfohlen für komplexe Modelle.`
- Zeile 17: `## ADVI`
- Zeile 21: `## Laplace`
- Zeile 26: `- **CRRT (TVCL)**: Schrittweite kleiner wählen, wenn Zeitprofile viele Sprünge haben.`
- Zeile 48: `- Risiko-Metrik simpel halten (Cmax>Limit schneller als AKI-Logit)`

### docs/PLACEHOLDERS_AUDIT.md
- Zeile 1: `# PLACEHOLDER & BASIS-IMPLEMENTATION AUDIT`
- Zeile 2: `Projektwurzel: `/mnt/data/tdmx-audit-phase5p4/tdmx-advanced-phase3``
- Zeile 4: `Diese Liste markiert Stellen mit Hinweisen auf Platzhalter, Demos, vereinfachte oder rudimentäre Implementierungen. Suchmuster: ADVI, AKI, BLQ, Beispiel, CRRT, DUMMY, Demo, FIXME, Heuristik, LLOQ, Michaelis.?Menten, Mixture, Platzhalter, Priors.*Platzhalter, QSS, Skeleton, Stub, TBD, TMDD, TODO, \.example, demo, dummy, example, example\.json, fallback, heuristic, missing, mock, nicht\s+abgedeckt, nicht\s+empfohlen, nicht\s+validiert, noch\s+nicht, not\s+implemented, not\s+recommended, nur\s+Demo, nur\s+Laplace, nur\s+UI, nur\s+als\s+Beispiel, nur\s+als\s+Skeleton, optional, placeholder, stub, t-Residuen, validiert, vereinfach, vereinfacht`
- Zeile 10: `- `config/users.yaml` — **1**`
- Zeile 41: `- Zeile 4: _Treffer_: `Demo``
- Zeile 51: `- **PK-Modelle:** 1C analytisch, 2C/3C via ODE, **CRRT** (zeitvariierende CL) für 2C/3C, **Michaelis–Menten (1C)**, **TMDD-QSS (1C, Skeleton)**.`
- Zeile 52: `- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).`
- Zeile 54: `- Zeile 8: _Treffer_: `Demo``
- Zeile 57: `- **PK-Modelle:** 1C analytisch, 2C/3C via ODE, **CRRT** (zeitvariierende CL) für 2C/3C, **Michaelis–Menten (1C)**, **TMDD-QSS (1C, Skeleton)**.`
- Zeile 58: `- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).`
- Zeile 59: `- **Fehler-Modelle:** additiv, proportional, kombiniert; **t-Residuen**, **Mixture**; **BLQ (M3)** via LLOQ.`
- Zeile 61: `- Zeile 9: _Treffer_: `t-Residuen``
- Zeile 64: `- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).`
- Zeile 65: `- **Fehler-Modelle:** additiv, proportional, kombiniert; **t-Residuen**, **Mixture**; **BLQ (M3)** via LLOQ.`
- Zeile 68: `- Zeile 15: _Treffer_: `Platzhalter``
- Zeile 71: `> 💡 **Platzhalter:** Pop-Priors & Thresholds in `priors/*.json` und `config/targets.json` sind **Beispieldaten**. Vor klinischem Einsatz bitte durch validierte Quellen ersetzen.`
- Zeile 80: `- Zeile 53: _Treffer_: `BLQ``
- Zeile 84: `- **Fehler/BLQ:** docs/ERROR_MODELS.md`
- Zeile 96: `- Zeile 10: _Treffer_: `example``
- Zeile 100: `- **.env.example** with `PG_DSN` environment variable.`
- Zeile 110: `- Zeile 33: _Treffer_: `BLQ``
- Zeile 114: `- BLQ (M3) via LLOQ-Checkbox, Likelihood-Anpassung (Laplace & Stan)`
- Zeile 115: `- Robuste Fehler: t-Residuen & Normal-Mixture`
- Zeile 117: `- Zeile 34: _Treffer_: `t-Residuen``
- Zeile 120: `- BLQ (M3) via LLOQ-Checkbox, Likelihood-Anpassung (Laplace & Stan)`
- Zeile 121: `- Robuste Fehler: t-Residuen & Normal-Mixture`
- Zeile 122: `- Schnellpfad: Stan-ADVI + Warm-Start Cache (digest, RDS)`
- Zeile 124: `- Zeile 35: _Treffer_: `ADVI``
- Zeile 127: `- Robuste Fehler: t-Residuen & Normal-Mixture`
- Zeile 128: `- Schnellpfad: Stan-ADVI + Warm-Start Cache (digest, RDS)`
- … (307 weitere Treffer)

### docs/PLACEHOLDERS_AUDIT_SUMMARY.json
- Zeile 15: `"file": "config/users.yaml",`

### docs/PRIORS_SCHEMA.md
- Zeile 25: `- TMDD (skeleton): **Kon, Koff, Rtot, Kint**.`

### docs/REPORTS.md
- Zeile 7: `- Parameter (Beispiel):`
- Zeile 42: `- Audit-Hash (optional), Version/Commit`

### docs/ROADMAP.md
- Zeile 8: `- **Phase 2**: **Diagnostik**, **BLQ (M3)**, robuste Fehler, **ADVI**, Cache, **Design-Optimierung**`
- Zeile 9: `- **Phase 3**: **Pädiatrie/Neonatal**, **CRRT**, **MM/TMDD (Skeleton)**, **Joint (CL↔Cr)**, **Site-Faktoren**`
- Zeile 18: `- HL7/FHIR-Connector (Patient/Medikation), LOINC/Units-Mapping`
- Zeile 19: `- FHIR Subscriptions (Event-getrieben), LIS/MIC-Ingestion`
- Zeile 21: `- DB-Versionierung, Antibiogramm-Feeds`
- Zeile 24: `- Unveränderlicher Audit (Hash/Merkle), e-Signaturen, feingranulare Rollen`

### docs/SECURITY.md
- Zeile 3: `Sicherheitsstatus (Demo) & Empfehlungen.`
- Zeile 6: `- **Auth**: Demo-Login (`config/users.yaml`, Klartext).`
- Zeile 8: `- **Audit**: CSV/DB, **nicht** kryptografisch gesichert.`
- Zeile 16: `- **e-Signaturen** & **unveränderlicher Audit** (Merkle-/Hash-Kette).`
- Zeile 29: `- **Passwörter:** Bitte `config/users.yaml` auf `password_hash` umstellen (`auth_upgrade_hashes()` kann einmalig konvertieren).`
- Zeile 30: `- **Audit:** Prüfsumme/Hash-Kette aktivieren (verwenden Sie `audit_append_hashchain()` statt Append ohne Hash).`
- Zeile 31: `- **DB:** Optional Audit in `audit_log` schreiben (Migration `003_audit.sql`).`

### docs/SETUP.md
- Zeile 8: `### Systempakete (Linux, Beispiel)`
- Zeile 49: `- **Stan-Toolchain fehlt** → Backend „Laplace“ oder „Stan-ADVI“ nutzen.`

### docs/TARGETS_PTA_CFR.md
- Zeile 8: `**Hinweis:** Default-Targets in `config/targets.json` sind **Platzhalter**.`
- Zeile 27: `- Meropenem: fT>MIC ≥ 50% (Demo).`
- Zeile 28: `- Vancomycin: AUC24/MIC 400–600 (Demo).`
- Zeile 31: `- AUC24 aus AUCτ skaliert (vereinfachend).`

### docs/TROUBLESHOOTING.md
- Zeile 7: `- **HMC sehr langsam** → Chains/Iter reduzieren, erst **ADVI** nutzen, Priors straffen.`
- Zeile 18: `## BLQ/LLOQ`
- Zeile 19: `- **BLQ ohne LLOQ** → Checkbox aus; oder LLOQ setzen.`
- Zeile 20: `- **Unplausible PTA bei BLQ** → Fehlermodell auf **t** oder **Mixture** stellen.`
- Zeile 22: `## Laplace/Hessian`
- Zeile 36: `- **zu langsam** → Laplace/ADVI, PPC-Reps reduzieren, PTA-Dose-Grid verkleinern.`

### models/stan/pk_multicpt_ode.stan
- Zeile 25: `int<lower=0,upper=1> is_blq[N];`
- Zeile 26: `real<lower=0> lloq;`
- Zeile 32: `int<lower=0> error_model; // 1=add,2=prop,3=comb,4=t-add,5=t-prop,6=mixture`
- Zeile 115: `} else { // mixture base sd uses sigma_add`
- Zeile 119: `if (is_blq[n] == 1) {`
- Zeile 120: `// M3: censored likelihood`
- Zeile 122: `target += normal_lcdf(lloq | pred[n], s);`
- Zeile 124: `// approx with normal CDF to keep model simple`
- Zeile 125: `target += normal_lcdf(lloq | pred[n], s);`
- Zeile 126: `} else { // mixture (two normal components)`
- Zeile 127: `target += log_sum_exp( log(mix_w) + normal_lcdf(lloq | pred[n], s),`
- Zeile 128: `log1m(mix_w) + normal_lcdf(lloq | pred[n], mix_scale * s) );`
- Zeile 135: `} else { // mixture`

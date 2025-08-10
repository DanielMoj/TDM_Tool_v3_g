# PLACEHOLDER & BASIS-IMPLEMENTATION AUDIT
Projektwurzel: `/mnt/data/tdmx-audit-phase5p4/tdmx-advanced-phase3`

Diese Liste markiert Stellen mit Hinweisen auf Platzhalter, Demos, vereinfachte oder rudimentäre Implementierungen. Suchmuster: ADVI, AKI, BLQ, Beispiel, CRRT, DUMMY, Demo, FIXME, Heuristik, LLOQ, Michaelis.?Menten, Mixture, Platzhalter, Priors.*Platzhalter, QSS, Skeleton, Stub, TBD, TMDD, TODO, \.example, demo, dummy, example, example\.json, fallback, heuristic, missing, mock, nicht\s+abgedeckt, nicht\s+empfohlen, nicht\s+validiert, noch\s+nicht, not\s+implemented, not\s+recommended, nur\s+Demo, nur\s+Laplace, nur\s+UI, nur\s+als\s+Beispiel, nur\s+als\s+Skeleton, optional, placeholder, stub, t-Residuen, validiert, vereinfach, vereinfacht

## Zusammenfassung (Anzahl Treffer pro Datei)
- `README.md` — **7**
- `README_PHASE0.md` — **8**
- `config/targets.json` — **3**
- `config/users.yaml` — **1**
- `docs/AI_HANDOFF.md` — **5**
- `docs/API.md` — **2**
- `docs/ARCHITECTURE.md` — **12**
- `docs/CHANGELOG.md` — **6**
- `docs/CONFIGURATION.md` — **14**
- `docs/CONTRIBUTING.md` — **1**
- `docs/DATAFLOW.md` — **7**
- `docs/DB_SCHEMA.md` — **5**
- `docs/DEPLOYMENT.md` — **2**
- `docs/DIAGNOSTICS.md` — **3**
- `docs/EHR_LIS.md` — **1**
- `docs/ERROR_MODELS.md` — **11**
- `docs/GLOSSARY.md` — **7**
- `docs/KNOWN_LIMITATIONS.md` — **7**
- `docs/MODELS_PK.md` — **9**
- `docs/OPTIMIZATION.md` — **1**
- `docs/PERFORMANCE.md` — **5**
- `docs/PRIORS_SCHEMA.md` — **3**
- `docs/REPORTS.md` — **2**
- `docs/ROADMAP.md` — **2**
- `docs/SECURITY.md` — **2**
- `docs/SETUP.md` — **6**
- `docs/TARGETS_PTA_CFR.md` — **5**
- `docs/TROUBLESHOOTING.md` — **5**
- `models/stan/pk_multicpt_ode.stan` — **11**

---
## Details nach Datei

### README.md
- Zeile 4: _Treffer_: `Demo`

```
Ein offenes **R/Shiny**-Framework für **Therapeutisches Drug Monitoring (TDM)** mit **Bayes-Inferenz**, simulierten **Konzentrations-Zeit-Profilen** und **PTA/CFR**-Auswertung. 
**Status:** Forschungs-/Demostand (nicht für klinische Entscheidungen validiert).
```
- Zeile 7: _Treffer_: `Skeleton`

```
## Highlights (Stand Phase 5)
- **PK-Modelle:** 1C analytisch, 2C/3C via ODE, **CRRT** (zeitvariierende CL) für 2C/3C, **Michaelis–Menten (1C)**, **TMDD-QSS (1C, Skeleton)**.
- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).
```
- Zeile 8: _Treffer_: `Demo`

```
- **PK-Modelle:** 1C analytisch, 2C/3C via ODE, **CRRT** (zeitvariierende CL) für 2C/3C, **Michaelis–Menten (1C)**, **TMDD-QSS (1C, Skeleton)**.
- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).
- **Fehler-Modelle:** additiv, proportional, kombiniert; **t-Residuen**, **Mixture**; **BLQ (M3)** via LLOQ.
```
- Zeile 9: _Treffer_: `t-Residuen`

```
- **Inferenz:** Laplace/MAP (schnell), **Stan (HMC)**, **Stan-ADVI** (variational, schnell), JAGS (1C-Demo).
- **Fehler-Modelle:** additiv, proportional, kombiniert; **t-Residuen**, **Mixture**; **BLQ (M3)** via LLOQ.
- **PTA & CFR:** fT>MIC, AUC24/MIC, Cmax/MIC; **Site-of-Infection**-Faktoren (Plasma/ELF/Bone/CSF).
```
- Zeile 15: _Treffer_: `Platzhalter`

```
> 💡 **Platzhalter:** Pop-Priors & Thresholds in `priors/*.json` und `config/targets.json` sind **Beispieldaten**. Vor klinischem Einsatz bitte durch validierte Quellen ersetzen.
```
- Zeile 24: _Treffer_: `optional`

```
))
# Optional Backends
# install.packages(c("cmdstanr","rstan","rjags"))
```
- Zeile 53: _Treffer_: `BLQ`

```
- **Targets & PTA/CFR:** docs/TARGETS_PTA_CFR.md  
- **Fehler/BLQ:** docs/ERROR_MODELS.md  
- **Diagnostik:** docs/DIAGNOSTICS.md
```

### README_PHASE0.md
- Zeile 6: _Treffer_: `optional`

```
- **Reporting helper** `R/reporting.R` wired into app (PDF render works).
- **DB scaffolding**: Postgres migrations `db/migrations/001_init.sql`, simple DAO `R/db.R` (optional).
- **Plumber API**: `api/plumber.R` with `/healthz`, `/fit`, `/predict`.
```
- Zeile 10: _Treffer_: `example`

```
- **renv bootstrap**: `scripts/setup.R` to create lockfile on your host.
- **.env.example** with `PG_DSN` environment variable.
- **Observability**: basic health doc; logs directory.
```
- Zeile 14: _Treffer_: `optional`

```
## Quickstart
1. (Optional) `Rscript scripts/setup.R` to create `renv.lock` locally.
2. Docker: `docker compose up --build` → Shiny at http://localhost:3838, API at http://localhost:8000.
```
- Zeile 33: _Treffer_: `BLQ`

```
- Diagnose-Tab: PPC, Rhat/ESS (wenn Stan), einfache Divergenz-Hinweise
- BLQ (M3) via LLOQ-Checkbox, Likelihood-Anpassung (Laplace & Stan)
- Robuste Fehler: t-Residuen & Normal-Mixture
```
- Zeile 34: _Treffer_: `t-Residuen`

```
- BLQ (M3) via LLOQ-Checkbox, Likelihood-Anpassung (Laplace & Stan)
- Robuste Fehler: t-Residuen & Normal-Mixture
- Schnellpfad: Stan-ADVI + Warm-Start Cache (digest, RDS)
```
- Zeile 35: _Treffer_: `ADVI`

```
- Robuste Fehler: t-Residuen & Normal-Mixture
- Schnellpfad: Stan-ADVI + Warm-Start Cache (digest, RDS)
- Design-Optimierung: Vorschlag nächster Samplingzeitpunkt
```
- Zeile 41: _Treffer_: `CRRT`

```
- Pädiatrie/Neonatal: Maturationsfunktion (sigmoidal auf CL), prior shifts
- Dialyse/CRRT: Zeitvariierende CL via Schedule (start:dauer:effluent:S), 2C/3C_CRRT
- Nichtlinearitäten: Michaelis-Menten (1C) + TMDD-QSS Skeleton (1C)
```
- Zeile 42: _Treffer_: `Skeleton`

```
- Dialyse/CRRT: Zeitvariierende CL via Schedule (start:dauer:effluent:S), 2C/3C_CRRT
- Nichtlinearitäten: Michaelis-Menten (1C) + TMDD-QSS Skeleton (1C)
- Joint-Coupling: weiche Kopplung CL ↔ Creatinin (Cockcroft-Gault)
```

### config/targets.json
- Zeile 6: _Treffer_: `Platzhalter`

```
"window": "tau",
    "notes": "Platzhalter; fT>MIC \u226550%"
  },
```
- Zeile 12: _Treffer_: `Platzhalter`

```
"threshold_max": 600.0,
    "notes": "Platzhalter; 400\u2013600 angestrebt"
  },
```
- Zeile 17: _Treffer_: `Platzhalter`

```
"threshold": 8.0,
    "notes": "Platzhalter; Ziel \u22658"
  }
```

### config/users.yaml
- Zeile 1: _Treffer_: `Demo`

```
# DEMO! Nicht für Produktion.
admin:
```

### docs/AI_HANDOFF.md
- Zeile 6: _Treffer_: `validiert`

```
## Ziel
Ein interaktives TDM-Tool (R/Shiny) mit Bayes-Inferenz, PTA/CFR, Diagnostik und Basiskonnektoren. **Nicht klinisch validiert.**
```
- Zeile 9: _Treffer_: `Skeleton`

```
## Was fertig ist (Phase 3)
- Siehe **README** und **CHANGELOG**. Kernpunkte: 1C/2C/3C (+CRRT/MM/TMDD-Skeleton), Laplace/Stan/ADVI, BLQ (M3), PTA/CFR, PPC, Report.
```
- Zeile 21: _Treffer_: `optional`

```
- `config/targets.json` (Ziele), `config/tissue.json` (Site), `priors/*.json` (Priors).  
- `.env`/`PG_DSN` für Postgres (optional).
```
- Zeile 28: _Treffer_: `Demo`

```
- MIC: 1.0 mg/L, Ziel: fT>MIC ≥ 0.5  
**Erwartet:** Fit läuft durch, Posterior-Summary angezeigt, PTA ~60–90% (Demo), Report-Button erzeugt PDF.
```
- Zeile 32: _Treffer_: `ADVI`

```
- **Do**: Priors/Targets **vor** klinischer Nutzung ersetzen; Einheiten prüfen; PPC & Diagnostik beachten.  
- **Don’t**: ADVI-Posterior ohne MCMC-Diagnostik als „wahr“ interpretieren.
```

### docs/API.md
- Zeile 71: _Treffer_: `ADVI`

```
## Hinweise
- **Timeouts**: Lange HMC-Läufe vermeiden, ggf. ADVI/Laplace nutzen.
- **Schema-Änderungen**: Backward-kompatibel halten; Beispielpayloads in Tests pinnen.
```
- Zeile 72: _Treffer_: `Beispiel`

```
- **Timeouts**: Lange HMC-Läufe vermeiden, ggf. ADVI/Laplace nutzen.
- **Schema-Änderungen**: Backward-kompatibel halten; Beispielpayloads in Tests pinnen.
```

### docs/ARCHITECTURE.md
- Zeile 8: _Treffer_: `CRRT`

```
- **Application/Controller:** server-Logik in `app.R` orchestriert Inputs → Priors → Inferenz → Outputs → Audit.
- **Domain (PK/Fehler/Kovariaten):** `R/pk_models.R`, `R/error_models.R`, `R/units_checks.R`, `R/pediatric.R`, `R/crrt.R`, `R/nonlinear.R`, `R/tissue.R`.
- **Inference:** `R/backend_bayes.R`, `models/stan/*.stan`, `models/jags/*.jags`, `R/cache.R`, `R/diagnostics.R`.
```
- Zeile 10: _Treffer_: `optional`

```
- **Inference:** `R/backend_bayes.R`, `models/stan/*.stan`, `models/jags/*.jags`, `R/cache.R`, `R/diagnostics.R`.
- **Data Access & Config:** `R/prior_db.R`, `config/*.json|yaml`, `R/db.R` (optional Postgres), `audit/audit_log.csv`.
- **Reporting:** `R/reporting.R`, `report/report.Rmd`.
```
- Zeile 20: _Treffer_: `CRRT`

```
pk_models.R      error_models.R units_checks.R utils.R
  pediatric.R      crrt.R         nonlinear.R    tissue.R
  joint.R          prior_db.R     audit.R        auth.R   reporting.R  db.R
```
- Zeile 33: _Treffer_: `TMDD`

```
## Komponenten (Kurzbeschreibung)
- **pk_models.R:** 1C analytisch; 2C/3C (ODE); *TVCL* für CRRT; Hooks für **MM** & **TMDD**.
- **error_models.R:** σ-Funktionen, **t-Residuen**, **Mixture**, **BLQ (M3)**-Likelihood.
```
- Zeile 34: _Treffer_: `t-Residuen`

```
- **pk_models.R:** 1C analytisch; 2C/3C (ODE); *TVCL* für CRRT; Hooks für **MM** & **TMDD**.
- **error_models.R:** σ-Funktionen, **t-Residuen**, **Mixture**, **BLQ (M3)**-Likelihood.
- **backend_bayes.R:** Laplace/MAP; Stan (HMC) & **Stan-ADVI**; JAGS-1C; Diagnostics; Warm-Start Cache.
```
- Zeile 35: _Treffer_: `ADVI`

```
- **error_models.R:** σ-Funktionen, **t-Residuen**, **Mixture**, **BLQ (M3)**-Likelihood.
- **backend_bayes.R:** Laplace/MAP; Stan (HMC) & **Stan-ADVI**; JAGS-1C; Diagnostics; Warm-Start Cache.
- **diagnostics.R:** **PPC**, R-hat/ESS-Tabelle.
```
- Zeile 39: _Treffer_: `CRRT`

```
- **pediatric.R:** Maturationsfunktion (sigmoid) & Prior-Shifts (Gewicht/PMA).
- **crrt.R:** Parser + CL(t)-Beitrag aus Effluent/Sieving.
- **nonlinear.R:** **MM (1C)** & **TMDD-QSS** (1C, Skeleton).
```
- Zeile 40: _Treffer_: `Skeleton`

```
- **crrt.R:** Parser + CL(t)-Beitrag aus Effluent/Sieving.
- **nonlinear.R:** **MM (1C)** & **TMDD-QSS** (1C, Skeleton).
- **joint.R:** weiche Kopplung CL ↔ Kreatinin (Penalty).
```
- Zeile 45: _Treffer_: `optional`

```
- **reporting.R:** PDF-Render-Helper.
- **db.R:** Optionale Postgres-DAO (Audit etc.).
- **plumber.R:** `/healthz`, `/fit`, `/predict`.
```
- Zeile 66: _Treffer_: `ADVI`

```
UI->>Backend: run_fit(obs, regimen, priors, ...)
  Backend->>Backend: MAP/HMC/ADVI (BLQ, Fehler)
  Backend->>PK: Posterior-Median → C(t)
```
- Zeile 74: _Treffer_: `optional`

```
## Erweiterungs-Punkte
- **Drug-Pakete:** `priors/<Drug>.json` + (optional) model-spezifische Parameter.
- **Modelle:** `pk_models.R` & `models/stan/*.stan` (weitere Kompartimente/Nichtlinearitäten).
```
- Zeile 80: _Treffer_: `optional`

```
## Technologiestack
- **R/Shiny**, **Stan** (cmdstanr/rstan), **JAGS**, **deSolve**, **plumber**, **Docker/Compose**, **Postgres** (optional).
```

### docs/CHANGELOG.md
- Zeile 7: _Treffer_: `CRRT`

```
- Pädiatrie/Neonatal: Maturationsfunktion & Prior-Shifts.
- Dialyse/CRRT: Zeitvariierende CL (2C_CRRT/3C_CRRT).
- Nichtlinear: Michaelis–Menten (1C), TMDD-QSS (1C, Skeleton).
```
- Zeile 8: _Treffer_: `Skeleton`

```
- Dialyse/CRRT: Zeitvariierende CL (2C_CRRT/3C_CRRT).
- Nichtlinear: Michaelis–Menten (1C), TMDD-QSS (1C, Skeleton).
- Joint-Kopplung: CL ↔ Kreatinin-Penalty.
```
- Zeile 11: _Treffer_: `CRRT`

```
- Gewebepenetration: Site-Faktoren (PTA/CFR).
- UI-Erweiterungen: Population, CRRT, Site, Kreatinin.
```
- Zeile 15: _Treffer_: `BLQ`

```
- Diagnostik-Tab: PPC, R-hat/ESS (Stan).
- BLQ (M3): LLOQ + zensierte Likelihood (R & Stan).
- Robuste Fehler: t-Residuen, Mixture.
```
- Zeile 16: _Treffer_: `t-Residuen`

```
- BLQ (M3): LLOQ + zensierte Likelihood (R & Stan).
- Robuste Fehler: t-Residuen, Mixture.
- Schnellpfad: Stan-ADVI + Warm-Start Cache.
```
- Zeile 17: _Treffer_: `ADVI`

```
- Robuste Fehler: t-Residuen, Mixture.
- Schnellpfad: Stan-ADVI + Warm-Start Cache.
- Design: Vorschlag nächster Samplingzeitpunkt.
```

### docs/CONFIGURATION.md
- Zeile 3: _Treffer_: `Beispiel`

```
Diese Datei beschreibt **alle Konfigurationsquellen**, deren **Priorität** und **Beispiele**.
```
- Zeile 12: _Treffer_: `Beispiel`

```
## Umgebungsvariablen
- `PG_DSN` – Postgres-DSN (optional). Beispiel:  
  `postgresql://tdmx:tdmx@db:5432/tdmx`
```
- Zeile 15: _Treffer_: `optional`

```
Wird in `R/db.R` gelesen. Ist die Variable leer oder DB nicht erreichbar, **fällt** das System auf dateibasierte Artefakte (CSV/JSON) zurück.
- `TDMX_AUDIT_PATH` – Pfad für Audit CSV (optional). Default: `audit/audit_log.csv`.
- `TDMX_CACHE_DIR` – Cache-Verzeichnis (optional). Default: `cache/`.
```
- Zeile 16: _Treffer_: `optional`

```
- `TDMX_AUDIT_PATH` – Pfad für Audit CSV (optional). Default: `audit/audit_log.csv`.
- `TDMX_CACHE_DIR` – Cache-Verzeichnis (optional). Default: `cache/`.
- `TDMX_STAN_CHAINS`, `TDMX_STAN_ITER` – Defaults für Stan (UI kann überschreiben).
```
- Zeile 20: _Treffer_: `Platzhalter`

```
## `config/targets.json`
Beispiel (Platzhalter):
```json
```
- Zeile 23: _Treffer_: `Demo`

```
{
  "Meropenem": {"metric": "fT>MIC", "threshold": 0.5, "window": "tau", "notes": "Demo"},
  "Vancomycin": {"metric": "AUC24/MIC", "threshold_min": 400, "threshold_max": 600}
```
- Zeile 28: _Treffer_: `Heuristik`

```
- Wird via `R/targets.R` geladen (`load_targets_cfg`).
- Mapping per Drug-Name oder Heuristik (Klassenregex).
```
- Zeile 40: _Treffer_: `Demo`

```
## `config/users.yaml` (Demo-Auth)
- Klartext-Benutzer nur für **Demo**. Für Produktion: `shinymanager`/SSO + Passwort-Hashes.
```
- Zeile 41: _Treffer_: `Demo`

```
## `config/users.yaml` (Demo-Auth)
- Klartext-Benutzer nur für **Demo**. Für Produktion: `shinymanager`/SSO + Passwort-Hashes.
```
- Zeile 49: _Treffer_: `CRRT`

```
- `options(current_site_name = input$site)` – Site-Faktoren.  
- `options(crrt_schedule_df = parse_crrt_schedule(...))` – CRRT-Profil.
```
- Zeile 52: _Treffer_: `ADVI`

```
## UI-Parameter (Ausschnitt)
- **Backend**: Laplace / Stan / Stan-ADVI / JAGS  
- **Residuen**: additiv / proportional / kombiniert / t-* / mixture
```
- Zeile 53: _Treffer_: `Mixture`

```
- **Backend**: Laplace / Stan / Stan-ADVI / JAGS  
- **Residuen**: additiv / proportional / kombiniert / t-* / mixture  
- **BLQ**: LLOQ + Checkbox „≤ LLOQ ist BLQ“
```
- Zeile 54: _Treffer_: `BLQ`

```
- **Residuen**: additiv / proportional / kombiniert / t-* / mixture  
- **BLQ**: LLOQ + Checkbox „≤ LLOQ ist BLQ“  
- **Cache**: Toggle „Warm-Start aktivieren“
```
- Zeile 58: _Treffer_: `Beispiel`

```
## Overrides & Beispiele
- Docker Compose setzt `PG_DSN` automatisch.
```

### docs/CONTRIBUTING.md
- Zeile 26: _Treffer_: `Beispiel`

```
- Keine PHI/Daten im Repo.  
- Beispiel-/synthetische Daten verwenden.
```

### docs/DATAFLOW.md
- Zeile 10: _Treffer_: `ADVI`

```
B --> C[Checks: Units & Plausibilität]
  C --> D[Backend: Laplace | Stan(HMC) | Stan-ADVI | JAGS]
  D --> E[Posterior-Draws]
```
- Zeile 19: _Treffer_: `BLQ`

```
**Validierung:** Einheiten/Zeiten/Konz. (`units_checks.R`).  
**BLQ:** LLOQ/Flags → Likelihood (M3) in R & Stan.  
**Caching:** Input-Hash → `cache/*.rds` (Warm-Start).
```
- Zeile 32: _Treffer_: `vereinfach`

```
**Site-Faktoren:** Plasma/ELF/Bone/CSF werden auf **Konzentrationen** angewendet (Skalierung).  
**AUC24:** Aus AUC über τ auf 24h skaliert (vereinfachend).
```
- Zeile 40: _Treffer_: `ADVI`

```
- **PPC:** yrep aus Draws + Fehlermodell → Observed vs Posterior-Mean.  
- **R-hat/ESS:** nur bei Stan-HMC; ADVI/Laplace liefern keine MCMC-Diagnostik.
```
- Zeile 53: _Treffer_: `fallback`

```
## Fehlerbehandlung & Fallbacks
- **Hessian** singulär → diagonale Σ, Warnung.
```
- Zeile 55: _Treffer_: `fallback`

```
- **Hessian** singulär → diagonale Σ, Warnung.  
- **Stan/JAGS** nicht vorhanden → Fallback auf **Laplace/ADVI**.  
- **ODE** Instabilität → `lsoda`-Defaults, Zeitgitter verdichten.
```
- Zeile 60: _Treffer_: `ADVI`

```
- **Laplace**: Subsekunden bis wenige Sekunden.  
- **Stan-ADVI**: schnell, gute Voransichten, aber ohne MCMC-Diagnostik.  
- **Stan-HMC**: verlässlichere Posterioren/Diagnostik, längere Laufzeit.
```

### docs/DB_SCHEMA.md
- Zeile 3: _Treffer_: `optional`

```
Datenbank-Layout (optional) für Persistenz von Fällen, Priors, Reports und Audit-Logs. Migration: `db/migrations/001_init.sql`.
```
- Zeile 15: _Treffer_: `optional`

```
priors ||--o{ cases : "by drug name"
  audit_log }}--|| cases : "ref via details.case_id (optional)"
```
```
- Zeile 27: _Treffer_: `optional`

```
- `created_at`, `updated_at` (timestamptz)  
- `patient_uid` (text, optional/pseudonymisiert)  
- `drug` (text), `model_type` (text), `backend` (text)
```
- Zeile 33: _Treffer_: `Beispiel`

```
**Beispiel-Insert**
```sql
```
- Zeile 63: _Treffer_: `validiert`

```
## Hinweise
- JSONB-Felder erlauben flexible Schemata, sollten aber via App **validiert** werden.  
- `draws_path` zeigt auf RDS/CSV im Filesystem; für große Draws besser externe Storage nutzen.
```

### docs/DEPLOYMENT.md
- Zeile 19: _Treffer_: `example`

```
- `PG_DSN=postgresql://tdmx:tdmx@db:5432/tdmx` (im Compose gesetzt)
- `.env.example` vorhanden (lokaler Betrieb ohne Compose).
```
- Zeile 33: _Treffer_: `Demo`

```
## Sicherheit (Hinweis)
- **Demo-Auth** (`config/users.yaml`) ist nicht produktionsreif.  
- Für Produktion: Reverse Proxy (TLS), SSO/OIDC, Secret-Management (Vault), gehärtete Images, Rate-Limits.
```

### docs/DIAGNOSTICS.md
- Zeile 6: _Treffer_: `optional`

```
- Zeige **Observed vs Posterior-Mean**; 1:1-Linie sollte grob getroffen werden.  
- Erweiterungen (optional): Dichte-Overlays, Tail-Proportionen.
```
- Zeile 13: _Treffer_: `ADVI`

```
## ADVI/Laplace
- **Keine** MCMC-Diagnostik (approx.). PPC prüft Plausibilität der Vorhersagen.
```
- Zeile 18: _Treffer_: `Mixture`

```
- R-hat hoch / ESS niedrig → mehr Iterationen, bessere Initialisierung, Priors straffen.  
- PPC stark off → Fehlermodell prüfen (t/Mixture), Kovariaten (CRCL, Gewicht), Datenqualität (Einheiten/Zeiten).
```

### docs/EHR_LIS.md
- Zeile 6: _Treffer_: `example`

```
- API: `api/plumber_phase5.R`.
- Konfig: `config/loinc_map.json`, `config/fhir.json.example`.
```

### docs/ERROR_MODELS.md
- Zeile 1: _Treffer_: `BLQ`

```
# FEHLERMODELLE & BLQ
```
- Zeile 10: _Treffer_: `Mixture`

```
- **t-additiv / t-proportional**: Student-t (df=ν), robust gegen Ausreißer.  
- **Mixture**: Mischung aus N(σ) und N(σ·scale), Gewicht w (robust gegen heavy tails).
```
- Zeile 12: _Treffer_: `BLQ`

```
## BLQ / M3
- **<LLOQ**-Werte werden als **zensiert** modelliert:
```
- Zeile 13: _Treffer_: `LLOQ`

```
## BLQ / M3
- **<LLOQ**-Werte werden als **zensiert** modelliert:  
  - Likelihood nutzt **CDF**: `P(Y < LLOQ)` statt Dichte in diesem Punkt.
```
- Zeile 14: _Treffer_: `LLOQ`

```
- **<LLOQ**-Werte werden als **zensiert** modelliert:  
  - Likelihood nutzt **CDF**: `P(Y < LLOQ)` statt Dichte in diesem Punkt.  
  - In **Stan** via `normal_lcdf`, in **R** analog.
```
- Zeile 18: _Treffer_: `Mixture`

```
## Implementierung
- R: `make_sigma_fun()`, `loglik_residuals_vec()` (inkl. BLQ & Mixture).  
- Stan: `error_model`-Codes (1=add, 2=prop, 3=comb, 4=t-add, 5=t-prop, 6=mixture).
```
- Zeile 19: _Treffer_: `Mixture`

```
- R: `make_sigma_fun()`, `loglik_residuals_vec()` (inkl. BLQ & Mixture).  
- Stan: `error_model`-Codes (1=add, 2=prop, 3=comb, 4=t-add, 5=t-prop, 6=mixture).
```
- Zeile 23: _Treffer_: `t-Residuen`

```
- **proportional/kombiniert**: breite Konzentrationsbereiche.  
- **t-Residuen/Mixture**: Ausreißer/Heavy Tails.  
- **BLQ aktivieren**, wenn Messwerte ≤ LLOQ vorliegen.
```
- Zeile 24: _Treffer_: `BLQ`

```
- **t-Residuen/Mixture**: Ausreißer/Heavy Tails.  
- **BLQ aktivieren**, wenn Messwerte ≤ LLOQ vorliegen.
```
- Zeile 27: _Treffer_: `Demo`

```
## Grenzen
- Mixture-Parameter (w, scale) sind heuristisch (Demo).  
- t-Residuen teilen df (ν) global; je nach Drug anpassbar.
```
- Zeile 28: _Treffer_: `t-Residuen`

```
- Mixture-Parameter (w, scale) sind heuristisch (Demo).  
- t-Residuen teilen df (ν) global; je nach Drug anpassbar.
```

### docs/GLOSSARY.md
- Zeile 7: _Treffer_: `BLQ`

```
- **AUC24/MIC** – AUC auf 24h skaliert, dividiert durch MIC.  
- **BLQ** – Below the Lower Limit of Quantification (<LLOQ).  
- **CFR** – Cumulative Fraction of Response (gegen MIC-Verteilung).
```
- Zeile 16: _Treffer_: `CRRT`

```
- **JAGS** – Just Another Gibbs Sampler.  
- **Kappa (κ)** – Skalenfaktor für CRRT-Beitrag zur CL.  
- **LLOQ** – Lower Limit of Quantification.
```
- Zeile 17: _Treffer_: `LLOQ`

```
- **Kappa (κ)** – Skalenfaktor für CRRT-Beitrag zur CL.  
- **LLOQ** – Lower Limit of Quantification.  
- **MAP** – Maximum a Posteriori (Laplace-Approximation).
```
- Zeile 20: _Treffer_: `Michaelis.?Menten`

```
- **MIC** – Minimal Inhibitory Concentration.  
- **MM** – Michaelis–Menten (nichtlineare Elimination).  
- **ODE** – Ordinary Differential Equation.
```
- Zeile 26: _Treffer_: `QSS`

```
- **Q1/Vp1** – Interkompartiment-Parameter für 2C.  
- **QSS** – Quasi-Steady State (TMDD-Näherung).  
- **Stan-ADVI** – Automatic Differentiation Variational Inference.
```
- Zeile 27: _Treffer_: `ADVI`

```
- **QSS** – Quasi-Steady State (TMDD-Näherung).  
- **Stan-ADVI** – Automatic Differentiation Variational Inference.  
- **TDM** – Therapeutisches Drug Monitoring.
```
- Zeile 29: _Treffer_: `TMDD`

```
- **TDM** – Therapeutisches Drug Monitoring.  
- **TMDD** – Target-Mediated Drug Disposition.  
- **TVCL** – Time-Varying Clearance (zeitvariable CL).
```

### docs/KNOWN_LIMITATIONS.md
- Zeile 6: _Treffer_: `Platzhalter`

```
## Klinische & Daten
- **Priors & Targets** sind **Platzhalter** (Demo) → nicht validiert für Klinik.  
- **CRRT-Modell** vereinfacht (CL = Baseline + κ·Effluent·S).
```
- Zeile 7: _Treffer_: `vereinfach`

```
- **Priors & Targets** sind **Platzhalter** (Demo) → nicht validiert für Klinik.  
- **CRRT-Modell** vereinfacht (CL = Baseline + κ·Effluent·S).  
- **TMDD** nur als **QSS-Skeleton**; keine validierte TMDD-Schätzung.
```
- Zeile 8: _Treffer_: `validiert`

```
- **CRRT-Modell** vereinfacht (CL = Baseline + κ·Effluent·S).  
- **TMDD** nur als **QSS-Skeleton**; keine validierte TMDD-Schätzung.  
- **Pädiatrie**: Maturationsfunktion generisch; keine Wirkstoff-spezifische Validierung.
```
- Zeile 13: _Treffer_: `ADVI`

```
## Statistik & Inferenz
- **Stan** deckt **TVCL/MM/TMDD** aktuell **nicht** ab (Laplace/ADVI only).  
- **Mixture/t-Residuen** Parameter sind heuristisch voreingestellt.
```
- Zeile 14: _Treffer_: `t-Residuen`

```
- **Stan** deckt **TVCL/MM/TMDD** aktuell **nicht** ab (Laplace/ADVI only).  
- **Mixture/t-Residuen** Parameter sind heuristisch voreingestellt.  
- **PPC** minimalistisch (Observed vs Mean), keine tail-Checks/overlays out-of-the-box.
```
- Zeile 18: _Treffer_: `optional`

```
## Integration & Infra
- **DB** optional, nur Grundschema; keine Migrationshistorie/Seeder.  
- **Auth** ist Demo (Klartext); **keine** SSO/e-Sign/eAudit.
```
- Zeile 19: _Treffer_: `Demo`

```
- **DB** optional, nur Grundschema; keine Migrationshistorie/Seeder.  
- **Auth** ist Demo (Klartext); **keine** SSO/e-Sign/eAudit.  
- **Audit** (CSV) ist nicht kryptografisch gesichert.
```

### docs/MODELS_PK.md
- Zeile 12: _Treffer_: `CRRT`

```
## Zeitvariierende Clearance (CRRT)
### 2C_CRRT / 3C_CRRT
```
- Zeile 13: _Treffer_: `CRRT`

```
## Zeitvariierende Clearance (CRRT)
### 2C_CRRT / 3C_CRRT
- **CL(t) = CL_base + κ·Effluent·S**, aus Zeitplan.
```
- Zeile 19: _Treffer_: `Michaelis.?Menten`

```
## Nichtlinearitäten
### Michaelis–Menten (MM, 1C)
- ODE: `dA = rate - (Vmax * C)/(Km + C) * Vc`.
```
- Zeile 23: _Treffer_: `Skeleton`

```
### TMDD-QSS (Skeleton, 1C)
- Effektive Clearance-Erhöhung bei hoher C (Konzeptdemo).
```
- Zeile 24: _Treffer_: `Demo`

```
### TMDD-QSS (Skeleton, 1C)
- Effektive Clearance-Erhöhung bei hoher C (Konzeptdemo).  
- Parameter: **Kon, Koff, Rtot, Kint**, **CL**, **Vc** (vereinfachend).
```
- Zeile 25: _Treffer_: `vereinfach`

```
- Effektive Clearance-Erhöhung bei hoher C (Konzeptdemo).  
- Parameter: **Kon, Koff, Rtot, Kint**, **CL**, **Vc** (vereinfachend).
```
- Zeile 33: _Treffer_: `TMDD`

```
## Unterstützung durch Backends
- **Stan (HMC)**: 1C/2C/3C ODE (ohne TVCL/MM/TMDD).  
- **Laplace/ADVI**: alle o. g. Pfade (demonstrativ); bei MM/TMDD/CRRT bevorzugt.
```
- Zeile 34: _Treffer_: `Demo`

```
- **Stan (HMC)**: 1C/2C/3C ODE (ohne TVCL/MM/TMDD).  
- **Laplace/ADVI**: alle o. g. Pfade (demonstrativ); bei MM/TMDD/CRRT bevorzugt.  
- **JAGS**: 1C (Demo).
```
- Zeile 35: _Treffer_: `Demo`

```
- **Laplace/ADVI**: alle o. g. Pfade (demonstrativ); bei MM/TMDD/CRRT bevorzugt.  
- **JAGS**: 1C (Demo).
```

### docs/OPTIMIZATION.md
- Zeile 8: _Treffer_: `Platzhalter`

```
- `generate_candidates`, `apply_constraints`
- `compute_pta_risk` (PTA + Risiko: `Cmax>limit` / `AUC24>limit` / `Vanco_AKI` Platzhalter)
- `pareto_front_idx`, `optimize_regimen`
```

### docs/PERFORMANCE.md
- Zeile 7: _Treffer_: `ADVI`

```
- **Laplace/MAP**: sehr schnell; gut für Routine/Exploration.  
- **Stan-ADVI**: schnell (variational); keine MCMC-Diagnostik.  
- **Stan (HMC)**: präziser/diagnostizierbar, aber langsamer.
```
- Zeile 9: _Treffer_: `Demo`

```
- **Stan (HMC)**: präziser/diagnostizierbar, aber langsamer.  
- **JAGS**: 1C-Demo; nicht empfohlen für komplexe Modelle.
```
- Zeile 17: _Treffer_: `ADVI`

```
## ADVI
- Gute Startpunkte; sinnvoll für **Schnellpfad**/Vorselektion.
```
- Zeile 26: _Treffer_: `CRRT`

```
- **2C/3C**: `lsoda`; bei Steifheit: Zeitgitter verdichten.  
- **CRRT (TVCL)**: Schrittweite kleiner wählen, wenn Zeitprofile viele Sprünge haben.  
- **Steady-State**-Simulation für PTA: 20·τ als Standard (anpassbar).
```
- Zeile 48: _Treffer_: `AKI`

```
- Gitter klein starten (8–12 Dosis, 5–7 τ, 2–4 tinf)
- Risiko-Metrik simpel halten (Cmax>Limit schneller als AKI-Logit)
- Draws subsamplen (200–400) für Interaktivität
```

### docs/PRIORS_SCHEMA.md
- Zeile 25: _Treffer_: `Skeleton`

```
- MM: **Vmax, Km** (falls genutzt).  
- TMDD (skeleton): **Kon, Koff, Rtot, Kint**.
```
- Zeile 28: _Treffer_: `validiert`

```
## Validierung
- Admin-Tab zeigt JSON an; Speicherung validiert:  
  - nur bekannte Parameter, fehlende als 0/NA,
```
- Zeile 35: _Treffer_: `optional`

```
2. Admin-Tab → laden/prüfen/speichern.  
3. (Optional) **targets.json** & **tissue.json** ergänzen.
```

### docs/REPORTS.md
- Zeile 7: _Treffer_: `Beispiel`

```
- Datei: `report/report.Rmd`
- Parameter (Beispiel):
```yaml
```
- Zeile 42: _Treffer_: `optional`

```
- PTA/CFR & Szenariovergleich  
- Audit-Hash (optional), Version/Commit
```

### docs/ROADMAP.md
- Zeile 8: _Treffer_: `ADVI`

```
- **Phase 1**: Targets, **PTA/CFR**, Dosing-Studio (Basis), Szenarien (Basis)
- **Phase 2**: **Diagnostik**, **BLQ (M3)**, robuste Fehler, **ADVI**, Cache, **Design-Optimierung**
- **Phase 3**: **Pädiatrie/Neonatal**, **CRRT**, **MM/TMDD (Skeleton)**, **Joint (CL↔Cr)**, **Site-Faktoren**
```
- Zeile 9: _Treffer_: `Skeleton`

```
- **Phase 2**: **Diagnostik**, **BLQ (M3)**, robuste Fehler, **ADVI**, Cache, **Design-Optimierung**
- **Phase 3**: **Pädiatrie/Neonatal**, **CRRT**, **MM/TMDD (Skeleton)**, **Joint (CL↔Cr)**, **Site-Faktoren**
```

### docs/SECURITY.md
- Zeile 3: _Treffer_: `Demo`

```
Sicherheitsstatus (Demo) & Empfehlungen.
```
- Zeile 6: _Treffer_: `Demo`

```
## Status
- **Auth**: Demo-Login (`config/users.yaml`, Klartext).  
- **Transport**: Keine TLS-Termination im Projekt (via Reverse Proxy lösen).
```

### docs/SETUP.md
- Zeile 6: _Treffer_: `optional`

```
- LaTeX/Pandoc (für PDF-Report)
- Optional: **cmdstanr/rstan** (Stan), **rjags** (JAGS)
```
- Zeile 8: _Treffer_: `Beispiel`

```
### Systempakete (Linux, Beispiel)
```bash
```
- Zeile 19: _Treffer_: `optional`

```
))
# Optional:
# install.packages(c("cmdstanr","rstan","rjags"))
```
- Zeile 28: _Treffer_: `optional`

```
## Stan einrichten (cmdstanr, optional)
```r
```
- Zeile 40: _Treffer_: `optional`

```
## renv (optional, reproduzierbar)
```r
```
- Zeile 49: _Treffer_: `ADVI`

```
## Troubleshooting (kurz)
- **Stan-Toolchain fehlt** → Backend „Laplace“ oder „Stan-ADVI“ nutzen.
- **PDF-Report schlägt fehl** → TinyTeX/Pandoc installieren; Logs prüfen.
```

### docs/TARGETS_PTA_CFR.md
- Zeile 8: _Treffer_: `Platzhalter`

```
**Hinweis:** Default-Targets in `config/targets.json` sind **Platzhalter**.
```
- Zeile 26: _Treffer_: `Beispiel`

```
## Beispiele
- Meropenem: fT>MIC ≥ 50% (Demo).
```
- Zeile 27: _Treffer_: `Demo`

```
## Beispiele
- Meropenem: fT>MIC ≥ 50% (Demo).  
- Vancomycin: AUC24/MIC 400–600 (Demo).
```
- Zeile 28: _Treffer_: `Demo`

```
- Meropenem: fT>MIC ≥ 50% (Demo).  
- Vancomycin: AUC24/MIC 400–600 (Demo).
```
- Zeile 31: _Treffer_: `vereinfach`

```
## Grenzen
- AUC24 aus AUCτ skaliert (vereinfachend).  
- MIC-Verteilungen klinikspezifisch → bitte **lokal** befüllen.
```

### docs/TROUBLESHOOTING.md
- Zeile 7: _Treffer_: `ADVI`

```
- **Fehler: Compiler nicht gefunden** → `cmdstanr::install_cmdstan()`; Xcode/Build-Essentials installieren.  
- **HMC sehr langsam** → Chains/Iter reduzieren, erst **ADVI** nutzen, Priors straffen.  
- **Divergenzen** → `adapt_delta` erhöhen, Reparametrisierung, Schrittweiten prüfen.
```
- Zeile 18: _Treffer_: `BLQ`

```
## BLQ/LLOQ
- **BLQ ohne LLOQ** → Checkbox aus; oder LLOQ setzen.
```
- Zeile 19: _Treffer_: `BLQ`

```
## BLQ/LLOQ
- **BLQ ohne LLOQ** → Checkbox aus; oder LLOQ setzen.  
- **Unplausible PTA bei BLQ** → Fehlermodell auf **t** oder **Mixture** stellen.
```
- Zeile 20: _Treffer_: `Mixture`

```
- **BLQ ohne LLOQ** → Checkbox aus; oder LLOQ setzen.  
- **Unplausible PTA bei BLQ** → Fehlermodell auf **t** oder **Mixture** stellen.
```
- Zeile 36: _Treffer_: `ADVI`

```
## Performance
- **zu langsam** → Laplace/ADVI, PPC-Reps reduzieren, PTA-Dose-Grid verkleinern.  
- **Cache deaktiviert**? → Toggle aktivieren.
```

### models/stan/pk_multicpt_ode.stan
- Zeile 25: _Treffer_: `BLQ`

```
vector[N] y;
  int<lower=0,upper=1> is_blq[N];
  real<lower=0> lloq;
```
- Zeile 26: _Treffer_: `LLOQ`

```
int<lower=0,upper=1> is_blq[N];
  real<lower=0> lloq;
  int<lower=1,upper=3> n_cmt;
```
- Zeile 32: _Treffer_: `Mixture`

```
vector[n_inf] rate;
  int<lower=0> error_model; // 1=add,2=prop,3=comb,4=t-add,5=t-prop,6=mixture
  int<lower=0,upper=1> est_sigma;
```
- Zeile 115: _Treffer_: `Mixture`

```
s = fmax(1e-6, sigma_prop * fabs(pred[n]));
    } else { // mixture base sd uses sigma_add
      s = sigma_add;
```
- Zeile 119: _Treffer_: `BLQ`

```
if (is_blq[n] == 1) {
      // M3: censored likelihood
```
- Zeile 122: _Treffer_: `LLOQ`

```
if (error_model <= 3) {
        target += normal_lcdf(lloq | pred[n], s);
      } else if (error_model == 4 || error_model == 5) {
```
- Zeile 125: _Treffer_: `LLOQ`

```
// approx with normal CDF to keep model simple
        target += normal_lcdf(lloq | pred[n], s);
      } else { // mixture (two normal components)
```
- Zeile 126: _Treffer_: `Mixture`

```
target += normal_lcdf(lloq | pred[n], s);
      } else { // mixture (two normal components)
        target += log_sum_exp( log(mix_w) + normal_lcdf(lloq | pred[n], s),
```
- Zeile 127: _Treffer_: `LLOQ`

```
} else { // mixture (two normal components)
        target += log_sum_exp( log(mix_w) + normal_lcdf(lloq | pred[n], s),
                               log1m(mix_w) + normal_lcdf(lloq | pred[n], mix_scale * s) );
```
- Zeile 128: _Treffer_: `LLOQ`

```
target += log_sum_exp( log(mix_w) + normal_lcdf(lloq | pred[n], s),
                               log1m(mix_w) + normal_lcdf(lloq | pred[n], mix_scale * s) );
      }
```
- Zeile 135: _Treffer_: `Mixture`

```
y[n] ~ student_t(nu, pred[n], s);
      } else { // mixture
        target += log_sum_exp( log(mix_w)   + normal_lpdf(y[n] | pred[n], s),
```

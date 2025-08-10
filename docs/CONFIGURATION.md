# CONFIGURATION

Diese Datei beschreibt **alle Konfigurationsquellen**, deren **Priorität** und **Beispiele**.

## Priorität (höchste zuerst)
1. **Umgebungsvariablen** (z. B. `PG_DSN`)
2. **Konfig-Dateien** in `config/` (`targets.json`, `tissue.json`, `users.yaml`)
3. **Runtime-Optionen** (via `options()`, z. B. `current_site_name` – gesetzt vom UI)
4. **Defaults im Code**

## Umgebungsvariablen
- `PG_DSN` – Postgres-DSN (optional). Beispiel:  
  `postgresql://tdmx:tdmx@db:5432/tdmx`  
  Wird in `R/db.R` gelesen. Ist die Variable leer oder DB nicht erreichbar, **fällt** das System auf dateibasierte Artefakte (CSV/JSON) zurück.
- `TDMX_AUDIT_PATH` – Pfad für Audit CSV (optional). Default: `audit/audit_log.csv`.
- `TDMX_CACHE_DIR` – Cache-Verzeichnis (optional). Default: `cache/`.
- `TDMX_STAN_CHAINS`, `TDMX_STAN_ITER` – Defaults für Stan (UI kann überschreiben).

## `config/targets.json`
Beispiel (Platzhalter):
```json
{
  "Meropenem": {"metric": "fT>MIC", "threshold": 0.5, "window": "tau", "notes": "Demo"},
  "Vancomycin": {"metric": "AUC24/MIC", "threshold_min": 400, "threshold_max": 600}
}
```
- Wird via `R/targets.R` geladen (`load_targets_cfg`).
- Mapping per Drug-Name oder Heuristik (Klassenregex).

## `config/tissue.json`
Site-Faktoren (Skalierung der Konzentrationen) je Drug, sonst `default`:
```json
{
  "default": {"Plasma": 1.0, "ELF": 0.6, "Bone": 0.3, "CSF": 0.2},
  "Meropenem": {"Plasma": 1.0, "ELF": 0.7, "Bone": 0.2, "CSF": 0.2}
}
```
- Zugriff via `load_tissue_cfg()` und `apply_site_penetration()`.

## `config/users.yaml` (Demo-Auth)
- Klartext-Benutzer nur für **Demo**. Für Produktion: `shinymanager`/SSO + Passwort-Hashes.

## Priors (`priors/*.json`)
- Siehe **docs/PRIORS_SCHEMA.md**. Admin-Tab kann JSON editieren, validieren, speichern.

## Runtime-Optionen (vom Server gesetzt)
- `options(current_drug_name = input$drug)` – für PTA/CFR.  
- `options(current_site_name = input$site)` – Site-Faktoren.  
- `options(crrt_schedule_df = parse_crrt_schedule(...))` – CRRT-Profil.

## UI-Parameter (Ausschnitt)
- **Backend**: Laplace / Stan / Stan-ADVI / JAGS  
- **Residuen**: additiv / proportional / kombiniert / t-* / mixture  
- **BLQ**: LLOQ + Checkbox „≤ LLOQ ist BLQ“  
- **Cache**: Toggle „Warm-Start aktivieren“  
- **Stan**: Chains, Iterationen

## Overrides & Beispiele
- Docker Compose setzt `PG_DSN` automatisch.  
- Lokal (Linux/Mac):  
  ```bash
  export PG_DSN="postgresql://tdmx:tdmx@localhost:5432/tdmx"
  R -q -e "shiny::runApp()"
  ```

# Phase 0 Deliverable

This package adds infrastructure scaffolding to tdmx-open-advanced:

- **Reporting helper** `R/reporting.R` wired into app (PDF render works).
- **DB scaffolding**: Postgres migrations `db/migrations/001_init.sql`, simple DAO `R/db.R` (optional).
- **Plumber API**: `api/plumber.R` with `/healthz`, `/fit`, `/predict`.
- **Docker**: `Dockerfile.app`, `Dockerfile.api`, `docker-compose.yml` (includes Postgres).
- **renv bootstrap**: `scripts/setup.R` to create lockfile on your host.
- **.env.example** with `PG_DSN` environment variable.
- **Observability**: basic health doc; logs directory.

## Quickstart
1. (Optional) `Rscript scripts/setup.R` to create `renv.lock` locally.
2. Docker: `docker compose up --build` → Shiny at http://localhost:3838, API at http://localhost:8000.
3. DB: run migration inside the db container or using `psql`:
   ```bash
   docker exec -i $(docker ps -qf name=_db_) psql -U tdmx -d tdmx < db/migrations/001_init.sql
   ```
4. App: use normally; report button now renders PDFs.

> Note: Job-Queue/async fits are planned next; current fits remain synchronous.


## Phase 1 additions
- PTA/CFR engine, target library, MIC handling
- Dosing-Studio (PTA vs Dose, basic)
- Scenario comparison (current vs alt1/alt2)


## Phase 2 additions
- Diagnose-Tab: PPC, Rhat/ESS (wenn Stan), einfache Divergenz-Hinweise
- BLQ (M3) via LLOQ-Checkbox, Likelihood-Anpassung (Laplace & Stan)
- Robuste Fehler: t-Residuen & Normal-Mixture
- Schnellpfad: Stan-ADVI + Warm-Start Cache (digest, RDS)
- Design-Optimierung: Vorschlag nächster Samplingzeitpunkt


## Phase 3 additions
- Pädiatrie/Neonatal: Maturationsfunktion (sigmoidal auf CL), prior shifts
- Dialyse/CRRT: Zeitvariierende CL via Schedule (start:dauer:effluent:S), 2C/3C_CRRT
- Nichtlinearitäten: Michaelis-Menten (1C) + TMDD-QSS Skeleton (1C)
- Joint-Coupling: weiche Kopplung CL ↔ Creatinin (Cockcroft-Gault)
- Gewebepenetration: Site-Faktoren (Plasma/ELF/Bone/CSF) via config/tissue.json; PTA/CFR nutzt Site-Konz.

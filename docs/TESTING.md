
# Testen des Projekts (Unit, Integration, E2E)

## Installation
```r
source("scripts/install_deps.R")
```

## Alles auf einmal ausführen
```r
# erzeugt JUnit XML, JSON Summary, Konsolen-Log, Coverage
source("scripts/run_all_tests.R")  # schreibt nach ./artifacts
```

## Nur E2E (Shiny)
```r
source("scripts/run_e2e_shiny.R")
```

## Nur API-Tests (Plumber)
```r
source("scripts/run_api_tests.R")
```

## Artefakte (für CI/andere KI)
- `artifacts/test-results.xml` (JUnit) – maschinenlesbar für CI/Analyse
- `artifacts/summary.json` – kompakte Übersicht (pro Test: pass/fail/skip/error/duration)
- `artifacts/console.log` – vollständige Ausgabe
- `artifacts/coverage.html` – Code-Coverage (best effort)

## Hinweise
- Tests skippen automatisch, wenn optionale Abhängigkeiten fehlen (z. B. cmdstanr, rjags, chromote).
- Für stabile E2E-Snapshots solltest du lokal **Chrome/Chromium** installiert haben (für `shinytest2`).

## Empfehlungen
- Erstelle **Simulations-Truth-Fälle** (synthetische Daten) je Modell, die im CI laufen (schnell, deterministisch).
- Nutze **seed**-Setzung in Tests (`set.seed(...)`) für Reproduzierbarkeit.
- Verwende in CI kleine Iterationszahlen (HMC/ADVI) über Optionen (z. B. `options(tdmx_hmc=...)`).

## CI (Beispiel GitHub Actions)
- Rufe `Rscript scripts/install_deps.R` und danach `Rscript scripts/run_all_tests.R artifacts` auf.
- Lade den Ordner `artifacts/` als Build-Artefakt hoch und parse `summary.json`/`test-results.xml`.

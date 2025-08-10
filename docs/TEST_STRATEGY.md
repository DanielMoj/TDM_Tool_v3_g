# TEST_STRATEGY

## Pyramide
- Unit: PK-Funktionen, Parser, Optimierung (schnell, deterministisch)
- Integration: Backends (Stan/JAGS), CFR-DB, FHIR (mit Skips)
- E2E: Shiny (shinytest2 Smoke/Snapshots), API

## Seeds & Limits
- `set.seed(123)`; HMC kurz via `options(tdmx_hmc=...)`

## Artefakte
- JUnit XML, summary.json, console.log, coverage.html (siehe AI_README)

## Skips
- Kein DB/FHIR? → Tests **skippen**, nicht failen (mit Begründung)

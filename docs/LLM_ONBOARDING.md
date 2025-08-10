# LLM_ONBOARDING

## Auftrag
- Tests ausführen, Artefakte liefern, zielgenaue Patches vorschlagen.

## Schritte
1) `source("scripts/install_deps.R")`
2) `options(tdmx_hmc=list(chains=2, iter_warmup=300, iter_sampling=300))`; `set.seed(123)`
3) `source("scripts/run_all_tests.R")`
4) Lese `artifacts/summary.json`, `test-results.xml`, `console.log`
5) Liefere Report im JSON-Format (siehe AI_README) + Patches (unified diff)

## Stilregeln
- Minimalinvasive Änderungen, Changelog-Eintrag, bestehende Schnittstellen wahren.

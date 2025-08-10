# RELEASE_PLAYBOOK

1) Tests grün: `scripts/run_all_tests.R`
2) `renv::snapshot()` (falls renv aktiv)
3) Release-Bundle bauen (Code + Priors + Checksums)
4) `docs/CHANGELOG.md` aktualisieren, Tag `vX.Y.Z`
5) Deploy (Docker/K8s), Smoke-Checks

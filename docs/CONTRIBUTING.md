# CONTRIBUTING

Danke für deinen Beitrag! Bitte beachte folgende Leitlinien, um Qualität und Reproduzierbarkeit zu sichern.

## Branching & Commits
- **main**: stabil, releasbar.
- **feature/***: pro Feature/Hotfix.
- **Conventional Commits**: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

## Code-Style
- **R**: klare Funktionsnamen, keine versteckten side-effects, `lintr`-sauber.  
- **Stan**: Parameter klar benennen, Constraints setzen, Prüfen mit kleinen Testdaten.  
- **Shiny**: Reaktive Ketten klein halten; `req()`/`validate()` nutzen.

## Tests
- **Unit**: `testthat` (PK-Funktionen, Fehler-Modelle, PTA/CFR).  
- **UI**: `shinytest2` für Kern-Flows (Fit → Plot → Report).  
- **Sim-Truth**: synthetische Datensätze mit bekannten Parametern.

## Dokumentation
- PRs aktualisieren relevante **docs/*.md**.  
- **CHANGELOG.md** updaten (Kategorie & kurze Beschreibung).

## Daten & Privacy
- Keine PHI/Daten im Repo.  
- Beispiel-/synthetische Daten verwenden.

## Review-Checkliste
- [ ] Läuft lokal (README Quickstart).  
- [ ] Keine Regressionen (Kern-Flows).  
- [ ] Tests grün.  
- [ ] Doku aktualisiert.  
- [ ] Priors/Targets **nicht** mit Fake-Werten für Produktivsysteme verwechselt.

## Issue-Tags (Vorschlag)
- `kind:bug`, `kind:feature`, `kind:docs`, `kind:infra`, `good first issue`, `help wanted`.

Viel Spaß beim Bauen!

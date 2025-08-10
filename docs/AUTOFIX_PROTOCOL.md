# AUTOFIX_PROTOCOL

1) Verstehe den Fehlschlag (Logs/JUnit/summary.json zitieren).
2) Reproduziere lokal (gleiche Seeds/Optionen).
3) Erstelle minimalen Patch (unified diff).
4) Führe Tests erneut aus; bei Erfolg: Changelog-Eintrag.
5) Reiche Patch + Begründung ein (Referenz auf Fehler & Tests).

## Patch-Format
Unified Diff – Beispiel:
```
--- a/R/backend_bayes.R
+++ b/R/backend_bayes.R
@@ -123,6 +123,9 @@
+  # Handle BLQ unter Mixture korrekt
+  if (error_model == 6 && any(is_blq==1)) { ... }
```

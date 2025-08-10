# KNOWN LIMITATIONS

Transparente Liste bekannter Lücken/Einschränkungen.

## Klinische & Daten
- **Priors & Targets** sind **Platzhalter** (Demo) → nicht validiert für Klinik.  
- **CRRT-Modell** vereinfacht (CL = Baseline + κ·Effluent·S).  
- **TMDD** nur als **QSS-Skeleton**; keine validierte TMDD-Schätzung.  
- **Pädiatrie**: Maturationsfunktion generisch; keine Wirkstoff-spezifische Validierung.  
- **Joint (CL↔Cr)**: weiche Penalty, kein vollständiges longitudinales Modell.

## Statistik & Inferenz
- **Stan** deckt **TVCL/MM/TMDD** aktuell **nicht** ab (Laplace/ADVI only).  
- **Mixture/t-Residuen** Parameter sind heuristisch voreingestellt.  
- **PPC** minimalistisch (Observed vs Mean), keine tail-Checks/overlays out-of-the-box.

## Integration & Infra
- **DB** optional, nur Grundschema; keine Migrationshistorie/Seeder.  
- **Auth** ist Demo (Klartext); **keine** SSO/e-Sign/eAudit.  
- **Audit** (CSV) ist nicht kryptografisch gesichert.  
- **API** minimal (nur `/fit`, `/predict`).

## UX
- Dosing-Studio rudimentär (PTA vs Dosis).  
- Szenario-Vergleich nur 3 Presets.

## Sonstiges
- Keine Unit-/UI-Tests im Repo (Templates geplant).  
- Kein Installer/Makefile; Docker deckt Hauptpfad ab.

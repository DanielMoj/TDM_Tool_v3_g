# DATA_DICTIONARY

## Patient & Kovariaten
| Feld | Typ | Einheit | Bereich/Beispiel |
|---|---|---|---|
| age | numeric | Jahre | 0–120 |
| weight | numeric | kg | 0.5–300 |
| height | numeric | cm | 20–250 |
| sex | factor | m/f/div | |
| scr | numeric | mg/dL | 0.1–20 |
| crcl | numeric | mL/min | 0–250 (Cockcroft-Gault) |
| renal_mod | factor | none/CRRT/HD | |

## Dosierung & Zeiten
| Feld | Typ | Einheit |
|---|---|---|
| dose | numeric | mg |
| tau | numeric | h |
| tinf | numeric | h |
| regimen_times | numeric[] | h |
| obs_times | numeric[] | h |
| obs_conc | numeric[] | mg/L |

## Ziele & MIC
| Feld | Typ | Einheit |
|---|---|---|
| mic | numeric | mg/L |
| target_type | factor | fT>MIC / AUC/MIC / Cmax/MIC |
| target_value | numeric | abhängig vom Wirkstoff |

## Einheiten
Alle Konzentrationen mg/L, Zeiten in Stunden. Siehe `R/units_checks.R`.

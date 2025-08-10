# FHIR_MAPPINGS

## Ressourcen
- `Patient`, `Observation` (Labore), optional `MedicationAdministration`

## Observation Codes (LOINC – Beispiel)
- Kreatinin: 2160-0
- Arzneistoffspiegel (generisch): 34714-6 (bitte site-spezifisch erweitern)

## Endpunkte
- `GET /Observation?patient=<id>&code=<codes>&_count=200` (+ Pagination via `link[rel=next]`)

## Mapping-Hinweise
- Einheiten harmonisieren (mg/L, ug/mL → mg/L).  
- Zeitstempel in UTC normalisieren.

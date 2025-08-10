# DB_SCHEMA_REFERENCE

## Tabellen

### antibiogram
| Spalte | Typ | Beschreibung |
|---|---|---|
| drug | text | Wirkstoffname |
| mic | numeric | MIC-Wert |
| prob | numeric | Wahrscheinlichkeit (Summe je Drug = 1) |
| source | text | Quelle (upload/api/…) |
| inserted_at | timestamptz | Default NOW() (optional) |

### dataset_versions
| Spalte | Typ | Beschreibung |
|---|---|---|
| kind | text | Datensatztyp (z. B. 'antibiogram') |
| version | text | Version (z. B. Zeitstempel) |
| checksum | text | SHA-256 |
| meta | jsonb | Metadaten (Quelle etc.) |
| inserted_at | timestamptz | Default NOW() |

### audit_log
Siehe `db/migrations/003_audit.sql` (Hash-Kette).

| Spalte | Typ |
|---|---|
| id | bigserial |
| ts | timestamptz |
| actor | text |
| action | text |
| payload | jsonb |
| prev_hash | text |
| hash | text |

## Beispiel-Queries
```sql
-- neueste Version der Antibiogramm-Daten
SELECT * FROM dataset_versions WHERE kind='antibiogram' ORDER BY inserted_at DESC LIMIT 1;

-- MIC-Verteilung für Meropenem
SELECT mic, prob FROM antibiogram WHERE drug='Meropenem' ORDER BY mic;
```

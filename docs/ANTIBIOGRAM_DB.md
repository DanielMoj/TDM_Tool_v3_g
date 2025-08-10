
# Antibiogramm-DB (CFR-Persistenz)

## Ziel
Antibiogramme (lokale MIC-Verteilungen) dauerhaft in **Postgres** speichern und in der App für **CFR/PTA** verwenden.

## Setup
- Pakete: `install.packages(c("DBI","RPostgres","digest"))`
- ENV: `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`
- Migration: `db/migrations/002_versioning.sql` (vorhanden)

## Nutzung (UI)
1. Tab **„Datenintegration“** → **Antibiogramm (CSV)** hochladen.  
2. **„CSV in DB importieren“** klicken → Import nach Postgres, Version wird in `dataset_versions` gespeichert.  
3. **„Liste aktualisieren“** → Drug aus DB wählen.  
4. **„DB-Verteilung übernehmen“** → MIC-Verteilungs-Text wird ins PTA/CFR-Feld geschrieben.

## Nutzung (API)
- `GET /lis/antibiogram/list` → verfügbare Drugs  
- `GET /lis/antibiogram/get?drug=Meropenem` → MIC-Verteilung  
- `POST /lis/antibiogram/import?path=/path/to.csv&source=myfeed` → Import

## Hinweise
- Verteilungen werden pro Upload normalisiert.  
- Versionierung: `dataset_versions(kind='antibiogram')`, `version=YYYYMMDDhhmmss`, `checksum=SHA256(JSON)`.

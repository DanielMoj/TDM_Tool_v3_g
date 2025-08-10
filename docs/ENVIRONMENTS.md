# ENVIRONMENTS

## DEV
- `PG*` auf lokale DB, `TDMX_JWT_SECRET=devsecret`
- Stan cmdstanr lokal installiert

## STAGING
- Getrennte DB, Seeds/Dummy-Daten, eingeschränkte Nutzer

## PROD
- Härtung: 2FA/MFA, Secrets aus Vault, restriktive Policies, Audit in DB + Backup

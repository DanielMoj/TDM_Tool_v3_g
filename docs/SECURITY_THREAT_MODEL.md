# SECURITY_THREAT_MODEL

## Angriffsoberflächen
- Shiny-App (Login, Session-TTL), Plumber-API (Bearer JWT), DB.
- Modell-/Priors-Dateien (Manipulation).

## Bedrohungen & Gegenmaßnahmen
- Credential Theft → Argon2-Hash (sodium), TTL, Rollen/Policies, 2FA (geplant).
- Token Replay → kurze Token-Lebensdauer, HTTPS, Secret-Rotation.
- Audit-Tampering → Hash-Kette + DB-Backup, Prüfroutine.
- DoS → Rate-Limits (geplant), Timeouts, parallele Chains begrenzen.

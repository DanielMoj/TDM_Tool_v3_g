# SECURITY

Sicherheitsstatus (Demo) & Empfehlungen.

## Status
- **Auth**: Demo-Login (`config/users.yaml`, Klartext).  
- **Transport**: Keine TLS-Termination im Projekt (via Reverse Proxy lösen).  
- **Audit**: CSV/DB, **nicht** kryptografisch gesichert.  
- **Rollen**: rudimentär; keine feingranulare Policies.  
- **Daten**: Keine PHI-Persistenz beabsichtigt; Pseudonymisierung empfohlen.

## Empfehlungen für Produktion
- **SSO/OIDC** (Keycloak/Azure AD), Passwort-Hashes, MFA.  
- **TLS** end-to-end (Ingress/Proxy), HSTS, sichere Ciphers.  
- **RBAC**: Rollen/Scopes (Admin/Clinician/Viewer), Break-Glass-Prozesse.  
- **e-Signaturen** & **unveränderlicher Audit** (Merkle-/Hash-Kette).  
- **Secrets**: Vault/KMS, Rotation, keine Secrets im Repo.  
- **SBOM** & Signierung (Container), regelmäßige Scans (Trivy/Grype).  
- **Datenlebenszyklus**: Retention, Löschkonzept, Backups, Verschlüsselung at-rest/in-transit.  
- **Logging**: PII-Reduktion, Redaction, Zugriffskontrolle.  
- **Rate-Limits/Throttling** an der API.

## DSGVO/Datenschutz
- Datenminimierung, Pseudonymisierung, TOMs, Auftragsverarbeitung klären.  
- Kein Export realer Personenbezüge ohne Rechtsgrundlage.


## Phase 6 Vorab-Hardening (dieser Commit)
- **Passwörter:** Bitte `config/users.yaml` auf `password_hash` umstellen (`auth_upgrade_hashes()` kann einmalig konvertieren). 
- **Audit:** Prüfsumme/Hash-Kette aktivieren (verwenden Sie `audit_append_hashchain()` statt Append ohne Hash). 
- **DB:** Optional Audit in `audit_log` schreiben (Migration `003_audit.sql`).

# RISK_REGISTER

| Risiko | Wahrscheinlichkeit | Impact | Maßnahme |
|---|---|---|---|
| Fehlparametrisierung Priors | mittel | hoch | Literaturabgleich, PPCs, Clin-Review |
| Divergenzen HMC | mittel | mittel | adapt_delta erhöhen, Reparametrisierung |
| FHIR-Änderungen | mittel | mittel | Robustere Parser, Subscriptions/Retry |
| DB-Ausfall | niedrig | mittel | Retry, Caching, Backups |
| Security/Leak | niedrig | hoch | Hashing (argon2), JWT-Secret, Least Privilege |

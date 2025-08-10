# CONSTRAINTS

- R/Shiny-basierte App; Stan/JAGS optional, aber bevorzugt Stan.
- Rechenbudget: HMC in CI mit kleinen Iterationen; Pathfinder/ADVI für schnelle Fitting-Pfade.
- Datenschutz: Pseudonymisierung; keine produktiven Patientendaten in Dev/CI.
- Lizenzen: Bibliotheken müssen kliniktauglich und auditierbar sein.

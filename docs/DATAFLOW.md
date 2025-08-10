# DATAFLOW

Diese Datei beschreibt die wichtigsten Datenflüsse und wo Validierung/Caching/Fehlerbehandlung greift.

## 1) TDM-Fit (End-to-End)
```mermaid
flowchart LR
  A[Input: Drug, Regimen, Obs, Kovariaten, Fehlermodell, Backend] --> B[Load Priors (JSON)]
  B --> C[Checks: Units & Plausibilität]
  C --> D[Backend: Laplace | Stan(HMC) | Stan-ADVI | JAGS]
  D --> E[Posterior-Draws]
  E --> F[Posterior-Summary]
  F --> G[PK-Prädiktion (Median-θ)]
  G --> H[Plots/Tabellen]
  D --> I[Diagnostics]
  A --> J[Audit: fit_start/fit_done]
```
**Validierung:** Einheiten/Zeiten/Konz. (`units_checks.R`).  
**BLQ:** LLOQ/Flags → Likelihood (M3) in R & Stan.  
**Caching:** Input-Hash → `cache/*.rds` (Warm-Start).

## 2) PTA/CFR
```mermaid
flowchart LR
  P[Posterior-Draws] --> Q[Monte-Carlo-Simulation]
  Q --> R[Metrics je Draw: fT>MIC, AUCτ, AUC24/MIC, Cmax/MIC]
  R --> S[Target-Check pro Draw]
  S --> T[PTA = Anteil Draws, die Target erfüllen]
  T --> U[CFR = Summe( PTA(MIC_i) * P(MIC_i) )]
```
**Site-Faktoren:** Plasma/ELF/Bone/CSF werden auf **Konzentrationen** angewendet (Skalierung).  
**AUC24:** Aus AUC über τ auf 24h skaliert (vereinfachend).

## 3) Dosing-Studio (Basis)
- Sweep **Dosis** um aktuellen Wert → **PTA vs Dosis**-Kurve.  
- Ziel-Linie (80%) als Orientierung.

## 4) Diagnostik
- **PPC:** yrep aus Draws + Fehlermodell → Observed vs Posterior-Mean.  
- **R-hat/ESS:** nur bei Stan-HMC; ADVI/Laplace liefern keine MCMC-Diagnostik.

## 5) Report (PDF)
- Button → `render_report_pdf()` → `report/report.Rmd` mit Parametern → PDF-Download.

## 6) API-Flows
### /fit (POST)
1. JSON parsen → Priors laden → `run_fit()` → Summary + Head der Draws.
2. Fehler → HTTP 400/500 mit Fehlermeldung.

### /predict (POST)
1. θ & Regimen & times → `predict_conc_grid()` → C(t).

## Fehlerbehandlung & Fallbacks
- **Hessian** singulär → diagonale Σ, Warnung.  
- **Stan/JAGS** nicht vorhanden → Fallback auf **Laplace/ADVI**.  
- **ODE** Instabilität → `lsoda`-Defaults, Zeitgitter verdichten.

## Performance-Hinweise
- **Laplace**: Subsekunden bis wenige Sekunden.  
- **Stan-ADVI**: schnell, gute Voransichten, aber ohne MCMC-Diagnostik.  
- **Stan-HMC**: verlässlichere Posterioren/Diagnostik, längere Laufzeit.

## Optimierung (Regime-Auswahl)
```mermaid
flowchart LR
  A[Posterior-Draws] --> B[Grid Dosis×τ×tinf]
  B --> C[Constraints (Infusionszeit/Tag, Tagesdosis, Gaben/Tag)]
  C --> D[PTA/Risiko je Regime]
  D --> E[Pareto (PTA↑, Risiko↓)]
  E --> F[Empfehlung + Heatmaps]
```

# PERFORMANCE

Empfehlungen zur Laufzeitoptimierung und Stabilität.

## Backends
- **Laplace/MAP**: sehr schnell; gut für Routine/Exploration.  
- **Stan-ADVI**: schnell (variational); keine MCMC-Diagnostik.  
- **Stan (HMC)**: präziser/diagnostizierbar, aber langsamer.  
- **JAGS**: 1C-Demo; nicht empfohlen für komplexe Modelle.

## Stan-Tuning (HMC)
- **Chains**: 4 (UI anpassbar).  
- **Iterationen**: warmup ≥ 500, sampling ≥ 1000.  
- **Parallelisierung**: `parallel_chains = n_cores`.  
- **Divergenzen**: `adapt_delta` erhöhen (z. B. 0.9→0.99), `max_treedepth` erhöhen.

## ADVI
- Gute Startpunkte; sinnvoll für **Schnellpfad**/Vorselektion.  
- Ergebnisse **nicht** als endgültige Evidenz ohne HMC-Diagnostik verwenden.

## Laplace
- Falls **Hessian** singulär: Priors straffen, Reparametrisieren, Startwerte auf log-Skala prüfen.

## ODE/Simulation
- **2C/3C**: `lsoda`; bei Steifheit: Zeitgitter verdichten.  
- **CRRT (TVCL)**: Schrittweite kleiner wählen, wenn Zeitprofile viele Sprünge haben.  
- **Steady-State**-Simulation für PTA: 20·τ als Standard (anpassbar).

## Caching
- Warm-Start via `cache/*.rds` (Input-Hash).  
- Cache invalidieren: einfach Datei löschen.

## Plots & PPC
- **PPC**: max. 200 yrep für schnelle Interaktivität.  
- **PTA vs Dosis**: 10–20 Stützstellen reichen meist.

## Hardware
- Mehr Kerne → mehr Chains / parallele Fits.  
- RAM-Anforderungen moderat (Posterior-Draws als DataFrames).

## Best Practices
- **Targets/Priors** realistisch halten → vermeidet Pathologien.  
- **Einheiten** (mg/L, h) konsequent prüfen.  
- **Seed** setzen für Reproduzierbarkeit (UI/Options).

## Optimierung (Gittergröße & Laufzeit)
- Gitter klein starten (8–12 Dosis, 5–7 τ, 2–4 tinf)
- Risiko-Metrik simpel halten (Cmax>Limit schneller als AKI-Logit)
- Draws subsamplen (200–400) für Interaktivität

# PK-MODELS

## Lineare Modelle
### 1-Kompartiment (1C, IV-Infusion)
- Analytische Lösung (Superposition).  
- Parameter: **CL**, **Vc**.

### 2-/3-Kompartiment (2C/3C, ODE)
- `deSolve::lsoda`; Infusion via Rate-Forcing.  
- Parameter: **CL**, **Vc**, **Q1**, **Vp1**, (**Q2**, **Vp2**).

## Zeitvariierende Clearance (CRRT)
### 2C_CRRT / 3C_CRRT
- **CL(t) = CL_base + κ·Effluent·S**, aus Zeitplan.  
- Eingabe per Textarea `start:dauer:effluent(L/h):S` pro Zeile.  
- Parameter zusätzlich: **kappa** (κ).

## Nichtlinearitäten
### Michaelis–Menten (MM, 1C)
- ODE: `dA = rate - (Vmax * C)/(Km + C) * Vc`.  
- Parameter: **Vmax**, **Km**, **Vc**.

### TMDD-QSS (Skeleton, 1C)
- Effektive Clearance-Erhöhung bei hoher C (Konzeptdemo).  
- Parameter: **Kon, Koff, Rtot, Kint**, **CL**, **Vc** (vereinfachend).

## Kovariaten
- **Allometrie**: `CL ~ (WT/70)^0.75`, `Vc ~ (WT/70)^1`.  
- **Neonatal**: Sigmoidale **Maturationsfunktion** (PMA in Wochen) auf CL.  
- **Joint-Penalty**: weiche Kopplung CL ↔ Kreatinin (Cockcroft-Gault).

## Unterstützung durch Backends
- **Stan (HMC)**: 1C/2C/3C ODE (ohne TVCL/MM/TMDD).  
- **Laplace/ADVI**: alle o. g. Pfade (demonstrativ); bei MM/TMDD/CRRT bevorzugt.  
- **JAGS**: 1C (Demo).

## Einheiten
- **Zeit**: Stunden, **Dosis**: mg, **Konzentration**: mg/L, **CL**: L/h, **Volumina**: L.

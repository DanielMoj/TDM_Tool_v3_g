# FEHLERMODELLE & BLQ

## Residualfehler
- **additiv**: σ = σ_add  
- **proportional**: σ = σ_prop · |pred|  
- **kombiniert**: σ = sqrt(σ_add² + (σ_prop·pred)²)

## Robuste Varianten
- **t-additiv / t-proportional**: Student-t (df=ν), robust gegen Ausreißer.  
- **Mixture**: Mischung aus N(σ) und N(σ·scale), Gewicht w (robust gegen heavy tails).

## BLQ / M3
- **<LLOQ**-Werte werden als **zensiert** modelliert:  
  - Likelihood nutzt **CDF**: `P(Y < LLOQ)` statt Dichte in diesem Punkt.  
  - In **Stan** via `normal_lcdf`, in **R** analog.

## Implementierung
- R: `make_sigma_fun()`, `loglik_residuals_vec()` (inkl. BLQ & Mixture).  
- Stan: `error_model`-Codes (1=add, 2=prop, 3=comb, 4=t-add, 5=t-prop, 6=mixture).

## Wahl der Modelle (Daumenregeln)
- **proportional/kombiniert**: breite Konzentrationsbereiche.  
- **t-Residuen/Mixture**: Ausreißer/Heavy Tails.  
- **BLQ aktivieren**, wenn Messwerte ≤ LLOQ vorliegen.

## Grenzen
- Mixture-Parameter (w, scale) sind heuristisch (Demo).  
- t-Residuen teilen df (ν) global; je nach Drug anpassbar.

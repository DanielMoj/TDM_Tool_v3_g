# DIAGNOSTIK

## Posterior Predictive Checks (PPC)
- Simuliere **yrep** aus Draws + Fehlermodell (σ).  
- Zeige **Observed vs Posterior-Mean**; 1:1-Linie sollte grob getroffen werden.  
- Erweiterungen (optional): Dichte-Overlays, Tail-Proportionen.

## MCMC-Diagnostik (Stan/HMC)
- **R-hat** nahe **1.00** (≤ 1.05).  
- **ESS** ausreichend (>> 200 je Parameter).  
- **Divergenzen**: In dieser Version nicht explizit dargestellt; bei Häufung: Schrittweite erhöhen, Reparametrisierung, Constraints prüfen.

## ADVI/Laplace
- **Keine** MCMC-Diagnostik (approx.). PPC prüft Plausibilität der Vorhersagen.

## Troubleshooting
- R-hat hoch / ESS niedrig → mehr Iterationen, bessere Initialisierung, Priors straffen.  
- PPC stark off → Fehlermodell prüfen (t/Mixture), Kovariaten (CRCL, Gewicht), Datenqualität (Einheiten/Zeiten).


## Pathfinder & BLQ
- Verwende *Stan-Pathfinder*, wenn HMC zu langsam ist, ADVI aber zu grob schätzt.
- BLQ (M3) unter t-Residuen nutzt jetzt `student_t_lcdf` für die Zensierungslikelihood.


## HMC/Stan-Diagnostik (neu)
- **HMC-Controls** in der UI (Chains, Warmup, Sampling, adapt_delta, max_treedepth).
- **Diagnose-Tab**: R-hat/ESS für Kernparameter, Divergenzen, max_treedepth, Stepsize.
- **Trace- & Rank-Histogramme** für CL, Vc (erweiterbar).

**Hinweise**
- Zielwerte: `R-hat ≤ 1.01`, `ESS_bulk` ausreichend groß (≥ 400).
- Divergenzen → adapt_delta erhöhen, Modell/oder Reparametrisierung prüfen.
- Viele `max_treedepth`-Hits → `max_treedepth` erhöhen oder Schrittweite/Parametrisierung anpassen.


### Hinweise JAGS-Fehlermodelle
- **t-Residuen:** `nu` (2–60) mit schwachem Uniform-Prior; robust bei Ausreißern.
- **Mixture:** zwei Normal-Komponenten mit `pi_mix` und Skalierungsfaktor `kappa` (σ2 = kappa·σ1).
- **BLQ:** Verwendung von `dinterval()` + Trunkierung `T(-Inf, LLOQ)`, dadurch stabile Zensierungslikelihood.
- **Adaptives dt:** Standard `dt_min=0.025h`, `dt_base=0.25h`, `refine_window=0.5h` – bei Performanceproblemen `dt_min` erhöhen.

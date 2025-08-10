# TROUBLESHOOTING

Pragmatische Lösungen zu häufigen Problemen.

## Stan/Toolchain
- **Fehler: Compiler nicht gefunden** → `cmdstanr::install_cmdstan()`; Xcode/Build-Essentials installieren.  
- **HMC sehr langsam** → Chains/Iter reduzieren, erst **ADVI** nutzen, Priors straffen.  
- **Divergenzen** → `adapt_delta` erhöhen, Reparametrisierung, Schrittweiten prüfen.

## rmarkdown/PDF
- **LaTeX fehlt** → `tinytex::install_tinytex()`; ggf. `xelatex` setzen.  
- **Umlaute** → UTF-8 & `xelatex` verwenden.

## ODE/Simulation
- **lsoda Warnungen** → Zeitgitter dichter; Randbedingungen prüfen; Infusionszeiten korrekt?  
- **Negative Konzentrationen** → Schrittweiten/Gleichungen prüfen; Fehlermodell vs. Daten checken.

## BLQ/LLOQ
- **BLQ ohne LLOQ** → Checkbox aus; oder LLOQ setzen.  
- **Unplausible PTA bei BLQ** → Fehlermodell auf **t** oder **Mixture** stellen.

## Laplace/Hessian
- **singulär** → Startwerte (theta) anpassen, Priors enger, Parameter fixieren/entkoppeln.

## Docker/DB
- **DB Connection refused** → Compose läuft? Port 5432 frei?  
- **Migration fehlgeschlagen** → `CREATE EXTENSION pgcrypto;` ausführen.  
- **API 500** → Logs im `api`-Container prüfen.

## Einheiten & Inputs
- Zeiten **in Stunden**, Konzentration **mg/L**, Dosis **mg**.  
- Regimen plausibel? (`tinf <= tau`, `n_doses >= 1`).  
- Beobachtungen: keine negativen Zeiten/Konz.

## Performance
- **zu langsam** → Laplace/ADVI, PPC-Reps reduzieren, PTA-Dose-Grid verkleinern.  
- **Cache deaktiviert**? → Toggle aktivieren.

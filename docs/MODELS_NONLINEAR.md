
# Nichtlineare PK-Modelle (MM/TMDD QSS)

## Varianten
- **MM-1C:** 1-Kompartiment, linearer CL + Michaelis–Menten-Elimination (`Vmax`, `Km`).
- **TMDD-QSS-1C:** 1-Kompartiment, linearer CL + **Target-Mediated Drug Disposition** im **QSS**-Approx.  
  Elimination: `kint * Rtot * C / (Kss + C)`.

Beide Varianten nutzen dieselbe Residualfehler- und BLQ-Logik wie die linearen Modelle (additiv, proportional, kombiniert, t-Fehler, Mixture).

## Priors
Falls `priors/*.json` die Parameter nicht enthalten, werden **fallback**-Priors genutzt (lognormal, schwach informativ):  
`CL, Vc, Vmax/Km` bzw. `CL, Vc, kint, Rtot, Kss`.  
Für reale Nutzung sollten substanzspezifische Priors gepflegt werden.

## Integration
- **Stan-Dateien:** `models/stan/pk_mm_onecpt_ode.stan`, `models/stan/pk_tmdd_qss_onecpt_ode.stan`
- **Backend:** `stan_file_for_model()`, `stan_data_list2()` wählen Stan-Datei & Datenlayout anhand `input$model_type`.
- **UI:** `selectInput("model_type", ...)` mit neuen Optionen „MM-1C“ und „TMDD-QSS-1C“.

## Hinweise
- TMDD-QSS reduziert auf saturierbare Elimination; Identifizierbarkeit erfordert informative Priors und ausreichende Daten.
- Für 2C/3C-Varianten der Nichtlinearitäten siehe Roadmap (kann nachgerüstet werden).

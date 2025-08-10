# REPORTS

PDF-Berichte werden über `rmarkdown` generiert.

## Template
- Datei: `report/report.Rmd`
- Parameter (Beispiel):
```yaml
params:
  title: "TDM Report"
  patient_uid: "PSEUDO-123"
  drug: "Meropenem"
  model_type: "2C"
  regimen: !r list(dose=1000,tau=8,tinf=0.5,n_doses=6,start_time=0)
  covariates: !r list(age=64, weight=80, crcl=90)
  observations: !r data.frame(time=c(1,7.5), conc=c(12.3,6.1))
  posterior_summary: !r list(median=c(CL=8,Vc=20,Q1=6,Vp1=12))
  targets: !r list(metric="fT>MIC", threshold=0.5)
  mic: 1.0
  pta: 0.82
  cfr: 0.74
```

## Rendern
```r
path <- render_report_pdf(
  rmd = "report/report.Rmd",
  params = list(title="TDM Report", drug="Meropenem", ...)
)
# Download/serve 'path'
```

## Branding
- Logo einbinden: YAML-Header (`logo: path/to/logo.png`) + `includes` (LaTeX).  
- Schrift/Seitenstil via `latex_engine: xelatex` und benutzerdefinierte `.tex`-Vorlagen.

## Inhalte (typisch)
- Patient/Regimen/Kovariaten (pseudonymisiert)  
- Posterior-Summary (Median/CI)  
- Konzentrations-Plot (Median + Beobachtungen)  
- PTA/CFR & Szenariovergleich  
- Audit-Hash (optional), Version/Commit

## Troubleshooting
- LaTeX-Fehler → `tinytex::reinstall_tinytex()`; Logs prüfen (`.log`).  
- Umlaute → UTF-8 sicherstellen, `xelatex` verwenden.

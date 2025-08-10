# SETUP

## Voraussetzungen
- **R ≥ 4.1**
- LaTeX/Pandoc (für PDF-Report)
- Optional: **cmdstanr/rstan** (Stan), **rjags** (JAGS)

### Systempakete (Linux, Beispiel)
```bash
sudo apt-get update && sudo apt-get install -y   build-essential g++ gfortran make   libcurl4-openssl-dev libssl-dev libxml2-dev   libfontconfig1-dev libharfbuzz-dev libfribidi-dev   pandoc
```

## Installation (ohne Docker)
```r
install.packages(c(
  "shiny","bslib","ggplot2","dplyr","DT","jsonlite","glue","readr","tibble","lubridate",
  "deSolve","numDeriv","MASS","rmarkdown","promises","future","zoo","posterior","bayesplot","digest","matrixStats"
))
# Optional:
# install.packages(c("cmdstanr","rstan","rjags"))
```

## Start
```r
shiny::runApp()
```

## Stan einrichten (cmdstanr, optional)
```r
install.packages("cmdstanr", repos = c("https://mc-stan.org/r-packages/", getOption("repos")))
cmdstanr::install_cmdstan()
```

## rmarkdown PDF
- LaTeX (TinyTeX) installieren:  
```r
install.packages("tinytex"); tinytex::install_tinytex()
```

## renv (optional, reproduzierbar)
```r
if (!requireNamespace("renv", quietly = TRUE)) install.packages("renv")
renv::init()
renv::install(c("shiny","deSolve", "cmdstanr"))
renv::snapshot()
```

## Troubleshooting (kurz)
- **Stan-Toolchain fehlt** → Backend „Laplace“ oder „Stan-ADVI“ nutzen.
- **PDF-Report schlägt fehl** → TinyTeX/Pandoc installieren; Logs prüfen.
- **ODE-Fehler** → Zeitskalen/Einheiten prüfen; kleinere Schrittweite (dt) verwenden.


### Zusätzliche Pakete für Fixes
```r
install.packages(c("sodium","digest"))
# Optional (DB): install.packages(c("DBI","RPostgres"))
```

# R/units_checks.R
validate_inputs_units <- function(regimen, obs) {
  if (regimen$dose <= 0) stop("Dosis muss > 0 mg sein.")
  if (regimen$tau <= 0) stop("Intervall tau muss > 0 h sein.")
  if (regimen$tinf < 0) stop("Infusionsdauer muss > 0 h sein.")
  if (regimen$n_doses < 1) stop("Anzahl Gaben muss >= 1 sein.")
  if (any(obs$time < 0)) stop("Messzeiten müssen >= 0 h sein.")
  if (any(obs$conc < 0)) stop("Konzentrationen müssen >= 0 mg/L sein.")
  TRUE
}

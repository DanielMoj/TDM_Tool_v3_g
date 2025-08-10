# R/pediatric.R
# Pediatric/Neonatal maturation functions and prior adjustments

# Simple sigmoid maturation on CL (PMA in weeks)
maturation_sigmoid <- function(PMA_weeks, TM50 = 47, Hill = 3) {
  # Anderson/Betha style sigmoid: (PMA^Hill) / (PMA^Hill + TM50^Hill)
  PMA_weeks <- pmax(10, PMA_weeks)
  (PMA_weeks^Hill) / (PMA_weeks^Hill + TM50^Hill)
}

# Adjust CL and Vc priors by covariates (age, weight, PMA, is_neonate)
adjust_priors_for_covariates <- function(priors, covariates) {
  pr <- priors
  mu <- pr$theta_log$mu
  # Allometry: already applied downstream, but we can shift prior mean to match expected scale
  wt <- covariates$weight %||% 70
  # Add neonatal maturation if provided
  PMA <- covariates$PMA_weeks %||% NA
  is_neon <- isTRUE(covariates$is_neonate)
  # shift CL mean on log scale
  if (!is.null(mu[["CL"]])) {
    shift <- 0
    # allometrische Erwartung
    shift <- shift + log((wt/70)^0.75)
    # maturation
    if (is_neon && is.finite(PMA)) {
      mat <- maturation_sigmoid(PMA)
      # scale relative to adult (=1)
      shift <- shift + log(pmax(0.1, mat))
    }
    mu[["CL"]] <- mu[["CL"]] + shift
  }
  if (!is.null(mu[["Vc"]])) {
    mu[["Vc"]] <- mu[["Vc"]] + log((wt/70)^1.0)
  }
  pr$theta_log$mu <- mu
  pr
}

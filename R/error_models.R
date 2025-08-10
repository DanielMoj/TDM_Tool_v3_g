# R/error_models.R
# Residualfehler: additiv, proportional, kombiniert
make_sigma_fun <- function(error_model, sigma_add, sigma_prop) {
  force(error_model); force(sigma_add); force(sigma_prop)
  if (identical(error_model, "additiv")) {
    function(pred) rep(sigma_add, length(pred))
  } else if (identical(error_model, "proportional")) {
    function(pred) pmax(1e-6, sigma_prop * abs(pred))
  } else {
    function(pred) sqrt(pmax(1e-12, sigma_add^2 + (sigma_prop * pred)^2))
  }
}

loglik_point <- function(y, mean, sd, error_model, nu = 4, mix_w = 0.9, mix_scale = 3) {
  if (error_model %in% c("additiv","proportional","kombiniert")) {
    return(dnorm(y, mean = mean, sd = sd, log = TRUE))
  } else if (grepl("^t", error_model)) {
    # Student-t with df=nu, scale = sd
    return(dt((y - mean)/sd, df = nu, log = TRUE) - log(sd))
  } else if (identical(error_model, "mixture")) {
    # mixture of N(mean, sd) and N(mean, mix_scale*sd)
    lp1 <- dnorm(y, mean = mean, sd = sd, log = TRUE)
    lp2 <- dnorm(y, mean = mean, sd = mix_scale*sd, log = TRUE)
    return(matrixStats::logSumExp(c(log(mix_w) + lp1, log(1 - mix_w) + lp2)))
  } else {
    return(dnorm(y, mean = mean, sd = sd, log = TRUE))
  }
}

# Vectorized loglik with BLQ support (M3)
loglik_residuals_vec <- function(y, pred, error_model, sigma_add, sigma_prop, lloq = NA_real_, is_blq = NULL, nu = 4, mix_w = 0.9, mix_scale = 3) {
  sigfun <- make_sigma_fun(error_model, sigma_add, sigma_prop)
  sig <- sigfun(pred)
  ll <- numeric(length(y))
  if (is.null(is_blq)) is_blq <- rep(FALSE, length(y))
  for (i in seq_along(y)) {
    if (isTRUE(is_blq[i])) {
      # M3: P(Y < LLOQ) = CDF value
      s <- sig[i]; m <- pred[i]
      if (grepl("^t", error_model)) {
        # approximate with normal CDF fallback for simplicity
        ll[i] <- pnorm((lloq - m)/s, log.p = TRUE)
      } else if (identical(error_model, "mixture")) {
        lp1 <- pnorm((lloq - m)/s, log.p = TRUE)
        lp2 <- pnorm((lloq - m)/(s*mix_scale), log.p = TRUE)
        ll[i] <- matrixStats::logSumExp(c(log(mix_w) + lp1, log(1 - mix_w) + lp2))
      } else {
        ll[i] <- pnorm((lloq - m)/s, log.p = TRUE)
      }
    } else {
      ll[i] <- loglik_point(y[i], pred[i], sig[i], error_model, nu, mix_w, mix_scale)
    }
  }
  sum(ll)
}

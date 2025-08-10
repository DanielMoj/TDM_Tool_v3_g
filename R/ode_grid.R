
# R/ode_grid.R - adaptive time grid for Euler integration (JAGS)

# Build an adaptive time grid around infusion and observation events.
# Returns list(t, dt, rate, idx)
build_time_grid_adaptive <- function(regimen, obs_times, dt_min = 0.025, dt_base = 0.25,
                                     refine_window = 0.5, horizon_extra = 1.0) {
  # regimen: list(dose, tau, tinf, n_doses, start_time)
  if (length(obs_times) == 0 || all(is.na(obs_times))) obs_times <- 0
  last_dose_end <- (regimen$start_time %||% 0) + (regimen$n_doses - 1) * regimen$tau + regimen$tinf
  t_end <- max(max(obs_times, na.rm = TRUE) + horizon_extra, last_dose_end + regimen$tau)
  # base grid
  Tbase <- seq(0, t_end, by = dt_base)
  # event times (infusion starts/ends + obs)
  t_events <- c()
  for (k in seq_len(regimen$n_doses)) {
    t0 <- (regimen$start_time %||% 0) + (k - 1) * regimen$tau
    t1 <- t0 + regimen$tinf
    t_events <- c(t_events, t0, t1)
  }
  t_events <- unique(c(t_events, obs_times))
  # refined grid around each event
  Tref <- c()
  for (te in t_events) {
    local <- seq(max(0, te - refine_window), min(t_end, te + refine_window), by = dt_min)
    Tref <- c(Tref, local, te)
  }
  Tseq <- sort(unique(round(c(Tbase, Tref, obs_times), digits = 6)))
  Nt <- length(Tseq)
  if (Nt < 2) stop("Time grid too short")
  dt <- diff(Tseq)
  # infusion rate (mg/h) at interval midpoints
  rate <- numeric(Nt - 1)
  for (i in seq_len(Nt - 1)) {
    tm <- (Tseq[i] + Tseq[i + 1]) / 2
    r <- 0
    for (k in seq_len(regimen$n_doses)) {
      t0 <- (regimen$start_time %||% 0) + (k - 1) * regimen$tau
      t1 <- t0 + regimen$tinf
      if (tm >= t0 && tm < t1) r <- r + regimen$dose / max(1e-12, regimen$tinf)
    }
    rate[i] <- r
  }
  # map observations to grid indices
  idx_obs <- vapply(obs_times, function(t) which.min(abs(Tseq - t)), integer(1))
  list(t = Tseq, dt = dt, rate = rate, idx = as.integer(idx_obs))
}

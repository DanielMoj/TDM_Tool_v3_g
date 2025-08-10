# R/pk_models.R
# Pharmakokinetische Modelle: 1C/2C/3C, ODE-basiert, Support für Infusionen

# Analytical 1C for infusion
conc_1c_inf_analytical <- function(t, dose, CL, Vc, tau, tinf, n_doses, start_time = 0) {
  k <- CL / Vc
  C <- numeric(length(t))
  for (i in 0:(n_doses - 1)) {
    t0 <- start_time + i * tau
    t1 <- t0 + tinf
    rate <- dose / tinf
    idx_during <- which(t >= t0 & t <= t1)
    idx_after <- which(t > t1 & t < t0 + tau)
    if (length(idx_during) > 0) {
      C[idx_during] <- C[idx_during] + (rate / CL) * (1 - exp(-k * (t[idx_during] - t0)))
    }
    if (length(idx_after) > 0) {
      C_end <- (rate / CL) * (1 - exp(-k * tinf))
      C[idx_after] <- C[idx_after] + C_end * exp(-k * (t[idx_after] - t1))
    }
  }
  C
}

# Multi-compartment via ODE
conc_profile_multi <- function(times, theta, regimen, model_type = "2C") {
  CL <- theta[["CL"]]; Vc <- theta[["Vc"]]
  Q1 <- theta[["Q1"]] %||% 0; Vp1 <- theta[["Vp1"]] %||% 1
  Q2 <- theta[["Q2"]] %||% 0; Vp2 <- theta[["Vp2"]] %||% 1
  k10 <- CL / Vc
  k12 <- ifelse(model_type %in% c("2C","3C"), Q1/Vc, 0)
  k21 <- ifelse(model_type %in% c("2C","3C"), Q1/Vp1, 0)
  k13 <- ifelse(model_type == "3C", Q2/Vc, 0)
  k31 <- ifelse(model_type == "3C", Q2/Vp2, 0)
  doses <- data.frame(
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = regimen$tinf,
    rate = regimen$dose / regimen$tinf
  )
  rhs <- function(t, A, pars) {
    rate <- 0
    if (nrow(doses) > 0) for (i in 1:nrow(doses)) {
      if (t > doses$t0[i] && t <= doses$t0[i] + doses$tinf[i]) rate <- rate + doses$rate[i]
    }
    dA1 <- rate - (k10 + k12 + k13) * A[1] + k21 * A[2] + k31 * A[3]
    dA2 <- k12 * A[1] - k21 * A[2]
    dA3 <- k13 * A[1] - k31 * A[3]
    list(c(dA1, dA2, dA3))
  }
  A0 <- c(0,0,0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}

# Michaelis-Menten 1C
conc_profile_mm <- function(times, theta, regimen) {
  CL <- theta[["CL"]]; Vc <- theta[["Vc"]]
  Vmax <- theta[["Vmax"]]; Km <- theta[["Km"]]
  doses <- data.frame(
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = regimen$tinf,
    rate = regimen$dose / regimen$tinf
  )
  rhs <- function(t, A, pars) {
    rate <- 0
    if (nrow(doses) > 0) for (i in 1:nrow(doses)) {
      if (t > doses$t0[i] && t <= doses$t0[i] + doses$tinf[i]) rate <- rate + doses$rate[i]
    }
    C <- A[1] / Vc
    dA1 <- rate - CL * C - (Vmax * C) / (Km + C)
    list(c(dA1))
  }
  A0 <- c(0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}

# TMDD-QSS 1C
conc_profile_tmdd_qss <- function(times, theta, regimen) {
  CL <- theta[["CL"]]; Vc <- theta[["Vc"]]
  kint <- theta[["kint"]]; Rtot <- theta[["Rtot"]]; Kss <- theta[["Kss"]]
  doses <- data.frame(
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = regimen$tinf,
    rate = regimen$dose / regimen$tinf
  )
  rhs <- function(t, A, pars) {
    rate <- 0
    if (nrow(doses) > 0) for (i in 1:nrow(doses)) {
      if (t > doses$t0[i] && t <= doses$t0[i] + doses$tinf[i]) rate <- rate + doses$rate[i]
    }
    C <- A[1] / Vc
    dA1 <- rate - CL * C - kint * Rtot * C / (Kss + C)
    list(c(dA1))
  }
  A0 <- c(0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}

# Generic PK prediction dispatcher
predict_conc_grid <- function(times, regimen, theta, model_type = "1C") {
  if (model_type == "1C") {
    conc_1c_inf_analytical(times, regimen$dose, theta[["CL"]], theta[["Vc"]], 
                          regimen$tau, regimen$tinf, regimen$n_doses, regimen$start_time)
  } else if (model_type %in% c("2C", "3C")) {
    conc_profile_multi(times, theta, regimen, model_type)
  } else if (model_type == "MM-1C") {
    conc_profile_mm(times, theta, regimen)
  } else if (model_type == "TMDD-QSS-1C") {
    conc_profile_tmdd_qss(times, theta, regimen)
  } else {
    stop("Unsupported model_type: ", model_type)
  }
}

# Find dose for target Cmax
find_dose_for_cmax <- function(theta, regimen, target_cmax, model_type = "1C", bounds = c(10, 10000)) {
  f <- function(dose) {
    reg <- regimen; reg$dose <- dose
    t_peak <- regimen$tinf
    conc <- predict_conc_grid(t_peak, reg, theta, model_type)
    conc - target_cmax
  }
  fl <- f(bounds[1]); fu <- f(bounds[2])
  if (fl * fu > 0) return(list(dose_mg = NA_real_))
  if (fl >= 0) return(list(dose_mg = bounds[1]))
  if (fu <= 0) return(list(dose_mg = NA_real_))
  # FIX: Replaced modern lambda syntax with function() for R < 4.1 compatibility
  result <- uniroot(f, lower = bounds[1], upper = bounds[2])
  list(dose_mg = result$root)
}

# ODE with time-varying clearance via function CL_fun(t)
conc_profile_multi_tvcl <- function(times, theta, regimen, model_type = "2C", CL_fun = NULL) {
  Vc <- theta[["Vc"]]; Q1 <- theta[["Q1"]] %||% 0; Vp1 <- theta[["Vp1"]] %||% 1
  Q2 <- theta[["Q2"]] %||% 0; Vp2 <- theta[["Vp2"]] %||% 1
  k12 <- ifelse(model_type %in% c("2C","3C"), Q1/Vc, 0)
  k21 <- ifelse(model_type %in% c("2C","3C"), Q1/Vp1, 0)
  k13 <- ifelse(model_type == "3C", Q2/Vc, 0)
  k31 <- ifelse(model_type == "3C", Q2/Vp2, 0)

  doses <- data.frame(
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = regimen$tinf,
    rate = regimen$dose / regimen$tinf
  )
  rhs <- function(t, A, pars) {
    rate <- 0
    if (nrow(doses) > 0) for (i in 1:nrow(doses)) {
      if (t > doses$t0[i] && t <= doses$t0[i] + doses$tinf[i]) rate <- rate + doses$rate[i]
    }
    CLt <- if (!is.null(CL_fun)) CL_fun(t) else theta[["CL"]]
    k10 <- CLt / Vc
    dA1 <- rate - (k10 + k12 + k13) * A[1] + k21 * A[2] + k31 * A[3]
    dA2 <- k12 * A[1] - k21 * A[2]
    dA3 <- k13 * A[1] - k31 * A[3]
    list(c(dA1, dA2, dA3))
  }
  A0 <- c(0,0,0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}
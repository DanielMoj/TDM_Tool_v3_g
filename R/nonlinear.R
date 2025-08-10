# R/nonlinear.R
# Nonlinear PK models: Michaelis-Menten (MM) and TMDD skeleton

# 1C with MM elimination (IV infusion)
conc_profile_mm_1c <- function(times, theta, regimen) {
  Vc  <- theta[["Vc"]]
  Vmax <- theta[["Vmax"]] %||% theta[["Vm"]] %||% 0
  Km   <- theta[["Km"]] %||% 1
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
    elim <- (Vmax * C)/(Km + C)
    dA1 <- rate - elim * Vc
    list(c(dA1))
  }
  A0 <- c(0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}

# Simple TMDD skeleton using quasi-steady-state (QSS) approximation
# Parameters: Vc, CL (linear), Kon, Koff, Rtot (target), Kint (internalization)
# For demo: we apply an effective clearance increase at high C
conc_profile_tmdd_1c_qss <- function(times, theta, regimen) {
  Vc <- theta[["Vc"]]; CL <- theta[["CL"]]
  Kon <- theta[["Kon"]] %||% 0.01
  Koff <- theta[["Koff"]] %||% 0.001
  Rtot <- theta[["Rtot"]] %||% 1
  Kint <- theta[["Kint"]] %||% 0.01
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
    # QSS effective clearance term
    Ceq <- (Koff + Kint) / Kon
    CL_tmdd <- (CL + (Rtot * Kint * C)/(C + Ceq))
    dA1 <- rate - (CL_tmdd * C)
    list(c(dA1))
  }
  A0 <- c(0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}

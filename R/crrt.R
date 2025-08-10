# R/crrt.R
# Time-varying clearance for Dialysis/CRRT via simple schedule

# Parse CRRT schedule from textarea:
# Format lines: start:duration:effluent(L/h):S (sieving coeff 0..1)
# Example: 0:8:2.0:0.8
parse_crrt_schedule <- function(txt) {
  if (is.null(txt) || !nzchar(txt)) return(data.frame())
  lines <- strsplit(txt, "\n")[[1]]
  df <- data.frame(start = numeric(0), dur = numeric(0), eff = numeric(0), S = numeric(0))
  for (ln in lines) {
    parts <- trimws(unlist(strsplit(ln, "[:]")))
    if (length(parts) < 3) next
    start <- as.numeric(parts[1]); dur <- as.numeric(parts[2]); eff <- as.numeric(parts[3])
    S <- if (length(parts) >= 4) as.numeric(parts[4]) else 0.7
    if (all(is.finite(c(start,dur,eff,S)))) {
      df <- rbind(df, data.frame(start=start, dur=dur, eff=eff, S=S))
    }
  }
  df
}

# Clearance contribution from CRRT (L/h) at time t, given schedule and coeff kappa
cl_crrt_fun <- function(schedule, kappa = 1.0) {
  function(t) {
    if (nrow(schedule) == 0) return(0)
    active <- which(t >= schedule$start & t <= (schedule$start + schedule$dur))
    if (length(active) == 0) return(0)
    # Simple model: CL_crrt = kappa * effluent_rate * mean(S)
    mean(schedule$eff[active] * schedule$S[active]) * kappa
  }
}


# Extended CRRT clearance model (CVVH, CVVHD, CVVHDF) with schedule
# mode: "CVVH" (convective), "CVVHD" (diffusive), "CVVHDF" (hybrid)
crrt_instant_cl <- function(mode = "CVVHDF", Q_uf = 0, Q_d = 0, S = 1, hematocrit = 0.3) {
  # Simplified formulas (drug in plasma water)
  # CVVH: CL ≈ S * Q_uf
  # CVVHD: CL ≈ S * Q_d
  # CVVHDF: CL ≈ S * (Q_uf + Q_d)
  q_plasma <- (1 - hematocrit)
  if (mode == "CVVH") return(S * Q_uf * q_plasma)
  if (mode == "CVVHD") return(S * Q_d * q_plasma)
  if (mode == "CVVHDF") return(S * (Q_uf + Q_d) * q_plasma)
  S * (Q_uf + Q_d) * q_plasma
}

# schedule: data.frame(t_start, t_end, mode, Q_uf, Q_d, S, hematocrit)
crrt_clearance_profile <- function(schedule) {
  if (is.null(schedule) || nrow(schedule) == 0) return(function(t) 0)
  function(t) {
    # returns CL_CRRT (L/h) at time t (h)
    for (i in seq_len(nrow(schedule))) {
      if (t >= schedule$t_start[i] && t < schedule$t_end[i]) {
        return(crrt_instant_cl(schedule$mode[i], schedule$Q_uf[i], schedule$Q_d[i], schedule$S[i], schedule$hematocrit[i]))
      }
    }
    0
  }
}

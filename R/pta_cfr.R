# R/pta_cfr.R
# PTA/CFR computation - PERFORMANCE OPTIMIZED VERSION

# Simulate steady-state over a long horizon and then compute last interval metrics
ss_window <- function(regimen, n_intervals = 20L, dt = 0.05) {
  list(
    times = seq(0, n_intervals * regimen$tau, by = dt),
    t_end  = n_intervals * regimen$tau
  )
}

# ===== PERFORMANCE OPTIMIZATION: Vectorized compute_metrics_for_draw =====
compute_metrics_for_draw <- function(theta, regimen, model_type, MIC) {
  # FIX: Added missing variable definition
  n_intervals <- 20L
  
  # simulate steady-state and take last interval
  win <- ss_window(regimen)
  conc <- predict_conc_grid(win$times, list(dose = regimen$dose, tau = regimen$tau, tinf = regimen$tinf,
                                            n_doses = n_intervals, start_time = 0),
                            theta, model_type)
  # apply site penetration factor
  drg <- getOption("current_drug_name", default = "Drug")
  st  <- getOption("current_site_name", default = "Plasma")
  conc <- apply_site_penetration(conc, drg, st, load_tissue_cfg("config/tissue.json"))
  # last interval [t_end - tau, t_end]
  t0 <- tail(win$times, 1) - regimen$tau
  idx <- which(win$times >= t0 - 1e-9)
  t_iv <- win$times[idx]
  c_iv <- conc[idx]
  # fT>MIC
  ft <- mean(c_iv > MIC)
  # AUC over last interval (tau), trapezoid
  auc_tau <- sum(diff(t_iv) * zoo::rollmean(c_iv, 2))
  # scale to 24h
  auc24 <- auc_tau * (24 / regimen$tau)
  # Cmax on last interval
  cmax <- max(c_iv)
  list(
    ft_gt_mic = ft,
    auc_tau = auc_tau,
    auc24 = auc24,
    auc24_over_mic = ifelse(MIC > 0, auc24 / MIC, Inf),
    cmax = cmax,
    cmax_over_mic = ifelse(MIC > 0, cmax / MIC, Inf)
  )
}

# ===== PERFORMANCE OPTIMIZATION: Vectorized PTA calculation =====
pta_for_regimen <- function(draws, regimen, model_type, target_def, MIC) {
  if (nrow(draws) == 0) return(NA_real_)
  
  # Vectorized approach using vapply for better performance
  ok <- vapply(seq_len(nrow(draws)), function(i) {
    th <- as.list(draws[i, , drop = FALSE])
    m <- compute_metrics_for_draw(th, regimen, model_type, MIC)
    meets_target(m, target_def)
  }, logical(1))
  
  mean(ok)
}

# Alternative highly vectorized version for simple targets
pta_for_regimen_vectorized <- function(draws, regimen, model_type, target_def, MIC) {
  if (nrow(draws) == 0) return(NA_real_)
  
  # Pre-allocate results matrix for all draws
  n_draws <- nrow(draws)
  metrics_list <- vector("list", n_draws)
  
  # Parallel computation if available
  if (requireNamespace("parallel", quietly = TRUE) && n_draws > 100) {
    n_cores <- min(parallel::detectCores() - 1, 4)
    cl <- parallel::makeCluster(n_cores)
    on.exit(parallel::stopCluster(cl))
    
    # Export necessary functions to cluster
    parallel::clusterExport(cl, c("compute_metrics_for_draw", "predict_conc_grid", 
                                  "apply_site_penetration", "ss_window", "meets_target"),
                           envir = environment())
    
    metrics_list <- parallel::parLapply(cl, seq_len(n_draws), function(i) {
      th <- as.list(draws[i, , drop = FALSE])
      compute_metrics_for_draw(th, regimen, model_type, MIC)
    })
    
    ok <- vapply(metrics_list, function(m) meets_target(m, target_def), logical(1))
  } else {
    # Sequential but vectorized computation
    ok <- vapply(seq_len(n_draws), function(i) {
      th <- as.list(draws[i, , drop = FALSE])
      m <- compute_metrics_for_draw(th, regimen, model_type, MIC)
      meets_target(m, target_def)
    }, logical(1))
  }
  
  mean(ok)
}
# ===== END PERFORMANCE OPTIMIZATION =====

parse_mic_distribution <- function(txt) {
  # format: "0.25:0.1, 0.5:0.2, 1:0.4, 2:0.3"
  if (is.null(txt) || !nzchar(txt)) return(NULL)
  parts <- unlist(strsplit(txt, ","))
  
  # Vectorized parsing
  vals <- t(sapply(parts, function(p) {
    kv <- trimws(unlist(strsplit(p, ":")))
    if (length(kv) != 2) return(c(NA, NA))
    c(as.numeric(kv[1]), as.numeric(kv[2]))
  }))
  
  if (is.null(dim(vals))) return(NULL)
  df <- data.frame(mic = as.numeric(vals[,1]), p = as.numeric(vals[,2]))
  df <- df[is.finite(df$mic) & is.finite(df$p) & df$p >= 0, , drop = FALSE]
  if (nrow(df) == 0) return(NULL)
  df$p <- df$p / sum(df$p)
  df
}

# ===== PERFORMANCE OPTIMIZATION: Vectorized CFR calculation =====
cfr_for_regimen <- function(draws, regimen, model_type, target_def, mic_dist) {
  if (is.null(mic_dist) || nrow(mic_dist) == 0) return(NA_real_)
  
  # Vectorized PTA calculation for all MIC values
  pta_vals <- vapply(seq_len(nrow(mic_dist)), function(i) {
    MIC <- mic_dist$mic[i]
    pta_for_regimen(draws, regimen, model_type, target_def, MIC)
  }, numeric(1))
  
  sum(pta_vals * mic_dist$p)
}

# Explore PTA vs dose grid (for Dosing-Studio basic)
# ===== PERFORMANCE OPTIMIZATION: Vectorized grid calculation =====
pta_vs_dose_grid <- function(draws, regimen, model_type, target_def, MIC, doses) {
  # Use vapply for better performance
  vapply(doses, function(d) {
    reg <- regimen
    reg$dose <- d
    pta_for_regimen(draws, reg, model_type, target_def, MIC)
  }, numeric(1))
}

# Backwards-compatibility shim for older tests
cfr_from_micdist <- function(draws, regimen, model_type, target, mic_df) {
  .Deprecated("cfr_for_regimen", package = "tdmx")
  cfr_for_regimen(draws, regimen, model_type, target, mic_df)
}

# ===== ADDITIONAL PERFORMANCE HELPERS =====

# Cached computation for repeated PTA calculations
.pta_cache <- new.env(parent = emptyenv())

pta_for_regimen_cached <- function(draws, regimen, model_type, target_def, MIC) {
  # Create cache key
  if (requireNamespace("digest", quietly = TRUE)) {
    key <- digest::digest(list(draws, regimen, model_type, target_def, MIC))
    
    # Check cache
    if (exists(key, envir = .pta_cache)) {
      return(.pta_cache[[key]])
    }
    
    # Compute and cache
    result <- pta_for_regimen(draws, regimen, model_type, target_def, MIC)
    .pta_cache[[key]] <- result
    return(result)
  } else {
    # No caching without digest
    return(pta_for_regimen(draws, regimen, model_type, target_def, MIC))
  }
}

# Clear PTA cache when needed
clear_pta_cache <- function() {
  rm(list = ls(envir = .pta_cache), envir = .pta_cache)
}

# Batch PTA computation for multiple regimens
pta_batch <- function(draws, regimens_list, model_type, target_def, MIC) {
  vapply(regimens_list, function(reg) {
    pta_for_regimen(draws, reg, model_type, target_def, MIC)
  }, numeric(1))
}
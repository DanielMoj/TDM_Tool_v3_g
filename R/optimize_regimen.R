# R/optimize_regimen.R
# Regimen optimization: infusion strategies, constraints, Pareto front, heatmaps

# --- Helpers --------------------------------------------------------------
strategy_label <- function(tinf, tau) {
  if (abs(tinf) < 1e-6) return("Bolus")
  if (tinf < 1.0) return("Kurzinfusion")
  if (tinf >= tau - 1e-6) return("Kontinuierlich")
  if (tinf >= 3.0) return("Verlängert")
  "Infusion"
}

daily_infusion_time <- function(dose, tau, tinf) {
  (24 / tau) * tinf
}

daily_dose_mg <- function(dose, tau) {
  (24 / tau) * dose
}

nurse_interactions_per_day <- function(tau) {
  24 / tau
}

# Generate candidate regimens given bounds and allowed strategies
generate_candidates <- function(base_regimen, dose_seq, tau_seq, tinf_seq, allow_continuous = TRUE) {
  regs <- list()
  for (d in dose_seq) for (ta in tau_seq) for (ti in tinf_seq) {
    tinf_eff <- if (allow_continuous && isTRUE(is.nan(ti))) ta else ti
    regs[[length(regs)+1]] <- list(dose = d, tau = ta, tinf = tinf_eff,
                                   n_doses = base_regimen$n_doses %||% 10L,
                                   start_time = base_regimen$start_time %||% 0)
  }
  regs
}

# Apply resource constraints
apply_constraints <- function(regs, max_daily_inf_h = Inf, max_daily_dose_mg = Inf, max_interactions = Inf) {
  keep <- lapply(regs, function(rg) {
    di <- daily_infusion_time(rg$dose, rg$tau, rg$tinf)
    dd <- daily_dose_mg(rg$dose, rg$tau)
    ni <- nurse_interactions_per_day(rg$tau)
    di <= max_daily_inf_h && dd <= max_daily_dose_mg && ni <= max_interactions
  })
  regs[unlist(keep)]
}

# Compute PTA and risk for one regimen
compute_pta_risk <- function(draws, regimen, model_type, target_def, MIC, risk_type = "Cmax>limit", risk_limit = 60, drug = "Drug") {
  pta <- pta_for_regimen(draws, regimen, model_type, target_def, MIC)
  # risk metric
  risk <- NA_real_
  if (risk_type == "Cmax>limit") {
    win <- list(times = seq(0, 20*regimen$tau, by = 0.1))
    cmax_flags <- logical(0)
    for (i in seq_len(min(nrow(draws), 400))) {
      th <- as.list(draws[i, , drop = FALSE])
      conc <- predict_conc_grid(win$times, modifyList(regimen, list(n_doses = 20L, start_time = 0)), th, model_type)
      drg <- getOption("current_drug_name", default = drug)
      st  <- getOption("current_site_name", default = "Plasma")
      conc <- apply_site_penetration(conc, drg, st, load_tissue_cfg("config/tissue.json"))
      t0 <- tail(win$times, 1) - regimen$tau
      idx <- which(win$times >= t0 - 1e-9)
      cmax_flags[i] <- max(conc[idx]) > risk_limit
    }
    risk <- mean(cmax_flags)
  } else if (risk_type == "AUC24>limit") {
    auc_flags <- logical(0)
    for (i in seq_len(min(nrow(draws), 400))) {
      th <- as.list(draws[i, , drop = FALSE])
      m <- compute_metrics_for_draw(th, regimen, model_type, MIC)
      auc_flags[i] <- m$auc24 > risk_limit
    }
    risk <- mean(auc_flags)
  } else if (risk_type == "Vanco_AKI") {
    cfg <- try(jsonlite::read_json("config/risk_models.json", simplifyVector = TRUE), silent = TRUE);
    prm <- if (!inherits(cfg,"try-error")) cfg$vanco_aki_logit else list(alpha=-7, beta=0.004);
    alpha <- prm$alpha; beta <- prm$beta
    px <- numeric(0)
    for (i in seq_len(min(nrow(draws), 400))) {
      th <- as.list(draws[i, , drop = FALSE])
      m <- compute_metrics_for_draw(th, regimen, model_type, MIC)
      p <- 1/(1 + exp(-(alpha + beta * m$auc24)))
      px[i] <- p
    }
    risk <- mean(px)
  }
  list(pta = pta, risk = risk)
}

# Build Pareto front (maximize PTA, minimize risk). Returns indices of nondominated.
pareto_front_idx <- function(pta, risk) {
  n <- length(pta)
  nd <- rep(TRUE, n)
  for (i in seq_len(n)) {
    for (j in seq_len(n)) {
      if (i == j) next
      if (!is.na(pta[j]) && !is.na(risk[j])) {
        if (pta[j] >= pta[i] && risk[j] <= risk[i] && (pta[j] > pta[i] || risk[j] < risk[i])) {
          nd[i] <- FALSE; break
        }
      }
    }
  }
  which(nd)
}

# Optimize: evaluate candidates, compute Pareto, choose recommendation
optimize_regimen <- function(draws, base_regimen, model_type, target_def, MIC,
                             dose_seq, tau_seq, tinf_seq, allow_cont = TRUE,
                             max_daily_inf_h = Inf, max_daily_dose_mg = Inf, max_interactions = Inf,
                             risk_type = "Cmax>limit", risk_limit = 60, pta_min = 0.8, drug = "Drug") {
  regs <- generate_candidates(base_regimen, dose_seq, tau_seq, tinf_seq, allow_cont)
  regs <- apply_constraints(regs, max_daily_inf_h, max_daily_dose_mg, max_interactions)
  if (length(regs) == 0) return(list(grid = data.frame(), pareto = data.frame(), rec = NULL))
  grid <- data.frame()
  for (k in seq_along(regs)) {
    rg <- regs[[k]]
    met <- compute_pta_risk(draws, rg, model_type, target_def, MIC, risk_type, risk_limit, drug = getOption("current_drug_name","Drug"))
    grid <- rbind(grid, data.frame(
      k = k, dose = rg$dose, tau = rg$tau, tinf = rg$tinf,
      PTA = met$pta, Risk = met$risk,
      daily_inf_h = daily_infusion_time(rg$dose, rg$tau, rg$tinf),
      daily_dose = daily_dose_mg(rg$dose, rg$tau),
      interactions = nurse_interactions_per_day(rg$tau),
      strategy = strategy_label(rg$tinf, rg$tau)
    ))
  }
  idx <- pareto_front_idx(grid$PTA, grid$Risk)
  pareto <- grid[idx, ]
  rec <- NULL
  feasible <- subset(grid, PTA >= pta_min)
  if (nrow(feasible) > 0) {
    j <- which.min(feasible$daily_inf_h + 1e-6 * feasible$daily_dose)
    rec <- feasible[j, ]
  } else {
    score <- 0.7 * (1 - grid$Risk) + 0.3 * grid$PTA
    j <- which.max(score)
    rec <- grid[j, ]
  }
  list(grid = grid, pareto = pareto, rec = rec)
}

# Heatmap builders
pta_heatmap_data <- function(draws, base_regimen, model_type, target_def, MIC, dose_seq, tau_fixed, tinf_seq) {
  rows <- list()
  for (d in dose_seq) for (ti in tinf_seq) {
    rg <- modifyList(base_regimen, list(dose = d, tau = tau_fixed, tinf = ti))
    pta <- pta_for_regimen(draws, rg, model_type, target_def, MIC)
    rows[[length(rows)+1]] <- data.frame(dose = d, tinf = ti, PTA = pta, tau = tau_fixed)
  }
  do.call(rbind, rows)
}

pta_heatmap_data_tau <- function(draws, base_regimen, model_type, target_def, MIC, dose_seq, tau_seq, tinf_fixed) {
  rows <- list()
  for (d in dose_seq) for (ta in tau_seq) {
    rg <- modifyList(base_regimen, list(dose = d, tau = ta, tinf = tinf_fixed))
    pta <- pta_for_regimen(draws, rg, model_type, target_def, MIC)
    rows[[length(rows)+1]] <- data.frame(dose = d, tau = ta, PTA = pta, tinf = tinf_fixed)
  }
  do.call(rbind, rows)
}
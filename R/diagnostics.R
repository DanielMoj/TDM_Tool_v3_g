# R/diagnostics.R
# Posterior predictive checks (PPC), R-hat/ESS table (if available), trace info proxies

# simple yrep generator for PPC: simulate predictive from draws (subset) and error model
yrep_matrix <- function(draws, obs, regimen, model_type, error_model = "kombiniert", sigma_add = 1.0, sigma_prop = 0.15, nrep = 200) {
  n <- nrow(obs); if (n == 0) return(matrix(numeric(0), nrow = 0, ncol = 0))
  idx <- sample(seq_len(nrow(draws)), size = min(nrep, nrow(draws)), replace = nrow(draws) < nrep)
  Y <- matrix(NA_real_, nrow = length(idx), ncol = n)
  sigfun <- make_sigma_fun(error_model, sigma_add, sigma_prop)
  for (i in seq_along(idx)) {
    th <- as.list(draws[idx[i], , drop = FALSE])
    pred <- predict_conc_grid(obs$time, regimen, th, model_type)
    sig <- sigfun(pred)
    Y[i, ] <- rnorm(n, mean = pred, sd = sig)
  }
  colnames(Y) <- paste0("yrep_", seq_len(n))
  Y
}

ppc_summary <- function(yrep, y) {
  if (length(yrep) == 0) return(data.frame())
  mu <- apply(yrep, 2, mean, na.rm = TRUE)
  sd <- apply(yrep, 2, sd, na.rm = TRUE)
  data.frame(obs = y, mean = mu, sd = sd, z = (y - mu)/sd)
}

# Rhat/ESS from backend diags if available
diag_table_from_backend <- function(diags) {
  if (is.null(diags) || length(diags) == 0) return(data.frame(Hinweis = "Keine Stan-Diagnostik verfügbar (Laplace/ADVI)."))
  df <- tryCatch(as.data.frame(diags), error = function(e) NULL)
  if (is.null(df) || nrow(df) == 0) return(data.frame(Hinweis = "Diagnostik leer."))
  df
}

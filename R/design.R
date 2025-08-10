# R/design.R
# Next optimal sampling time suggestion (simple D-opt proxy using posterior draws)
library(numDeriv)

predict_point <- function(theta, regimen, t, model_type) {
  reg <- regimen
  reg$n_doses <- 20L
  reg$start_time <- 0
  predict_conc_grid(t, reg, theta, model_type)
}

pred_var_over_draws <- function(draws, regimen, t, model_type) {
  vals <- sapply(1:min(nrow(draws), 400), function(i) {
    theta <- as.list(draws[i, , drop = FALSE])
    predict_point(theta, regimen, t, model_type)
  })
  stats::var(vals, na.rm = TRUE)
}

suggest_next_time <- function(draws, regimen, model_type, window_from, window_to, by = 0.25) {
  grid <- seq(window_from, window_to, by = by)
  if (length(grid) == 0) return(list(t_best = NA_real_, var_pred = NA_real_, grid = numeric(0), var = numeric(0)))
  vars <- sapply(grid, function(t) pred_var_over_draws(draws, regimen, t, model_type))
  j <- which.max(vars)
  list(t_best = grid[j], var_pred = vars[j], grid = grid, var = vars)
}

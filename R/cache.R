# R/cache.R
# Simple warm-start cache by hashed key
get_cache_path <- function(key) file.path("cache", paste0(key, ".rds"))

cache_key_for_fit <- function(obs, regimen, priors, model_type, error_model, covariates, backend, estimate_sigma, sigma_init) {
  if (!requireNamespace("digest", quietly = TRUE)) return(NULL)
  obj <- list(obs = obs, regimen = regimen, priors = priors, model_type = model_type, error_model = error_model,
              covariates = covariates, backend = backend, estimate_sigma = estimate_sigma, sigma_init = sigma_init)
  digest::digest(obj, algo = "xxhash64")
}

cache_get <- function(key) {
  path <- get_cache_path(key); if (!file.exists(path)) return(NULL)
  readRDS(path)
}

cache_put <- function(key, value) {
  if (is.null(key)) return(invisible(FALSE))
  dir.create("cache", showWarnings = FALSE, recursive = TRUE)
  saveRDS(value, file = get_cache_path(key))
  invisible(TRUE)
}

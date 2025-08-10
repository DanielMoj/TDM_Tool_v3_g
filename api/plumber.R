# api/plumber.R
# Plumber API exposing fit/predict endpoints
library(plumber)
source(file.path("R","utils.R"), chdir = TRUE)
source(file.path("R","prior_db.R"), chdir = TRUE)
source(file.path("R","error_models.R"), chdir = TRUE)
source(file.path("R","pk_models.R"), chdir = TRUE)
source(file.path("R","backend_bayes.R"), chdir = TRUE)

#* Health check
#* @get /healthz
function() list(status = "ok", time = as.character(Sys.time()))

#* Fit model and return posterior summary
#* @post /fit
function(req, res) {
  body <- jsonlite::fromJSON(req$postBody, simplifyVector = TRUE)
  priors <- load_priors("priors")
  drug <- body$drug
  if (is.null(priors[[drug]])) {
    res$status <- 400
    return(list(error = "unknown drug"))
  }
  obs <- tibble::tibble(time = body$obs$time, conc = body$obs$conc)
  regimen <- body$regimen
  covars <- body$covariates
  backend <- body$backend %||% "Laplace"
  error_model <- body$error_model %||% "kombiniert"
  estimate_sigma <- body$estimate_sigma %||% TRUE
  sigma_init <- body$sigma_init %||% list(add = 1.0, prop = 0.15)
  res_fit <- run_fit(obs, regimen, priors[[drug]], body$model_type, error_model, covars, backend, estimate_sigma, sigma_init)
  list(posterior_summary = res_fit$posterior_summary, draws_head = head(res_fit$draws, 10))
}

#* Predict concentration-time on a grid given parameters
#* @post /predict
function(req, res) {
  body <- jsonlite::fromJSON(req$postBody, simplifyVector = TRUE)
  theta <- body$theta
  times <- body$times
  regimen <- body$regimen
  model_type <- body$model_type
  pred <- predict_conc_grid(times, regimen, theta, model_type)
  list(time = times, conc = pred)
}

# Phase 5 endpoints
if (file.exists("api/plumber_phase5.R")) source("api/plumber_phase5.R")

# Auth layer
if (file.exists("api/plumber_auth.R")) source("api/plumber_auth.R")

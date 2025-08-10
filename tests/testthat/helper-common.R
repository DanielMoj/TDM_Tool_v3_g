# Common helpers for tests
# Source utils.R to get the %||% operator
source(file.path("R", "utils.R"))

skip_if_no_cmdstan <- function() {
  testthat::skip_if_not_installed("cmdstanr")
  ok <- try(cmdstanr::cmdstan_version() >= "2.31", silent = TRUE)
  if (inherits(ok,"try-error") || isFALSE(ok)) testthat::skip("cmdstanr not set up")
}

skip_if_no_jags <- function() {
  testthat::skip_if_not_installed("rjags")
}

make_temp_dir <- function(prefix="tdmx-test-") {
  td <- file.path(tempdir(), paste0(prefix, as.integer(runif(1,1e6,1e7))))
  dir.create(td, recursive = TRUE, showWarnings = FALSE)
  td
}

load_sources <- function() {
  source(file.path("R","pk_models.R"), chdir=TRUE)
  source(file.path("R","pta_cfr.R"), chdir=TRUE)
  source(file.path("R","optimize_regimen.R"), chdir=TRUE)
  source(file.path("R","units_checks.R"), chdir=TRUE)
  source(file.path("R","antibiogram.R"), chdir=TRUE)
  source(file.path("R","fhir.R"), chdir=TRUE)
  source(file.path("R","backend_bayes.R"), chdir=TRUE)
  source(file.path("R","ode_grid.R"), chdir=TRUE, local=TRUE)
  source(file.path("R","auth.R"), chdir=TRUE)
  source(file.path("R","audit.R"), chdir=TRUE)
  invisible(TRUE)
}
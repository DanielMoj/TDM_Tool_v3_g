test_that("Stan-Pathfinder produces draws quickly", {
  load_sources()
  skip_if_no_cmdstan()
  options(tdmx_hmc = list(chains = 2L, iter_warmup = 200L, iter_sampling = 200L, adapt_delta = 0.9, max_treedepth = 10L))
  obs <- data.frame(time = c(2,6,7), conc = c(8,12,10))
  reg <- list(dose=1000, tau=8, tinf=1, n_doses=6, start_time=0)
  pri <- list(
    theta = list(CL=6, Vc=30),
    theta_log = list(
      mu = list(CL=log(6), Vc=log(30)),
      sd = list(CL=0.3, Vc=0.3)
    )
  )
  res <- run_fit(obs=obs, regimen=reg, priors=pri, model_type="1C",
                 error_model=1, covariates=list(), backend="Stan-Pathfinder",
                 estimate_sigma=TRUE, sigma_init=list(add=1.0, prop=0.1),
                 blq_lloq=NA_real_, is_blq=NULL, use_cache=TRUE)
  expect_true(is.data.frame(res$draws))
  expect_gt(nrow(res$draws), 10)
})

test_that("JAGS backend runs for MM-1C with adaptive grid", {
  load_sources()
  skip_if_no_jags()
  obs <- list(times=c(2,6,7), conc=c(8,12,10), is_blq=c(0,0,0), lloq=NA_real_)
  reg <- list(dose=800, tau=8, tinf=1, n_doses=6, start_time=0)
  pri <- list(theta = c(CL=log(6), Vc=log(35), Vmax=log(2000), Km=log(10)), omega=diag(4))
  res <- run_fit(obs, reg, priors=pri, model_type="MM-1C", backend="JAGS", error_model=4, covariates=list(), estimate_sigma=TRUE, sigma_init=2)
  expect_true(is.data.frame(res$draws) || is.list(res$draws))
})


test_that("PTA and CFR functions run and return [0,1]", {
  load_sources()
  set.seed(123)
  draws <- data.frame(CL = exp(rnorm(300, log(5), 0.2)), Vc = exp(rnorm(300, log(30), 0.2)))
  reg <- list(dose=1000, tau=8, tinf=1, n_doses=8, start_time=0)
  target <- list(type="AUC/MIC", cutoff=125)
  mic <- 1
  p <- pta_for_regimen(draws, reg, "1C", target, mic)
  expect_true(is.finite(p))
  expect_gte(p, 0); expect_lte(p, 1)
  # CFR with a simple MIC distribution
  df <- data.frame(mic=c(0.25,0.5,1,2), prob=c(0.2,0.3,0.3,0.2))
  cfr <- cfr_for_regimen(draws, reg, "1C", target, df)
  expect_true(is.finite(cfr))
  expect_gte(cfr, 0); expect_lte(cfr, 1)
})

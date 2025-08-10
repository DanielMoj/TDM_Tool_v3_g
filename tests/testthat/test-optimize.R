
test_that("optimize_regimen yields a recommendation", {
  load_sources()
  set.seed(1)
  draws <- data.frame(CL = exp(rnorm(300, log(6), 0.3)), Vc = exp(rnorm(300, log(35), 0.3)))
  base_regimen <- list(dose=1000, tau=8, tinf=1, n_doses=10, start_time=0)
  res <- optimize_regimen(draws, base_regimen, "1C", list(metric="AUC24/MIC", threshold_min=125), MIC=1,
                          dose_seq=seq(500,2000,by=500), tau_seq=c(6,8,12), tinf_seq=c(0.5,3,NaN),
                          allow_cont=TRUE, pta_min=0.5)
  expect_true(is.data.frame(res$grid))
  expect_true(nrow(res$grid) > 0)
  expect_true(is.null(res$rec) || all(c("dose","tau","tinf","PTA","Risk") %in% names(res$rec)))
})

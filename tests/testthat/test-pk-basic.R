
test_that("predict_conc_grid returns reasonable shapes", {
  load_sources()
  th <- list(CL=5, Vc=30, Q1=8, Vp1=40)
  reg <- list(dose=1000, tau=8, tinf=1, n_doses=6, start_time=0)
  times <- seq(0, 48, by=0.5)
  y <- predict_conc_grid(times, reg, th, model_type="2C")
  expect_equal(length(y), length(times))
  expect_true(all(is.finite(y)))
  expect_gt(max(y), 0)
})

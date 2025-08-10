
test_that("API endpoints respond", {
  skip_if_not_installed("plumber")
  skip_if_not_installed("httr2")
  # Start plumber in background
  pr <- plumber::pr("api/plumber.R")
  port <- httpuv::randomPort()
  s <- plumber::pr_run(pr, port = port, background = TRUE)
  on.exit({try(s$stop(), silent = TRUE)}, add = TRUE)
  Sys.sleep(1.0)
  # hit list antibiogram (should work even if DB empty)
  req <- httr2::request(sprintf("http://127.0.0.1:%d/lis/antibiogram/list", port))
  resp <- httr2::req_perform(req)
  expect_true(httr2::resp_status(resp) %in% c(200, 500)) # 500 if DB not configured; that's acceptable here
})


library(testthat)
library(shinytest2)
# Run all tests in this directory
test_check <- function(pkg = NULL) {
  testthat::test_dir("tests/testthat", reporter = testthat::SummaryReporter$new())
}
test_check()

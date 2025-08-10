
# Run only API tests
dir.create("artifacts", showWarnings = FALSE, recursive = TRUE)
testthat::test_file("tests/testthat/test-api.R", reporter = testthat::JunitReporter$new(file="artifacts/api.xml"))

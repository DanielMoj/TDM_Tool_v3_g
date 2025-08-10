
# Run only the shinytest2 e2e test(s)
dir.create("artifacts", showWarnings = FALSE, recursive = TRUE)
testthat::test_file("tests/testthat/test-e2e-shiny.R", reporter = testthat::JunitReporter$new(file="artifacts/e2e-shiny.xml"))

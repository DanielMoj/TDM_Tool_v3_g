
args <- commandArgs(trailingOnly = TRUE)
art <- if (length(args)) args[[1]] else "artifacts"
dir.create(art, showWarnings = FALSE, recursive = TRUE)
library(testthat)

# Run unit/integration tests with JUnit xml + summary json
xml_file <- file.path(art, "test-results.xml")
json_file <- file.path(art, "summary.json")
sink_file <- file.path(art, "console.log")

jr <- testthat::JunitReporter$new(file = xml_file)
lr <- testthat::ListReporter$new()
sr <- testthat::SummaryReporter$new()

sink(sink_file)
res <- testthat::test_dir("tests/testthat", reporter = testthat::MultiReporter$new(reporters = list(jr, lr, sr)))
sink()

# Build JSON summary
summ <- lapply(lr$results, function(x) {
  list(
    file = x$filename %||% NA_character_,
    test = x$test %||% NA_character_,
    passed = length(x$expectations) - sum(vapply(x$expectations, testthat::expectation_broken, logical(1))) ,
    failed = sum(vapply(x$expectations, testthat::expectation_failure, logical(1))),
    warnings = sum(vapply(x$expectations, testthat::expectation_warning, logical(1))),
    skips = sum(vapply(x$expectations, testthat::expectation_skipped, logical(1))),
    errors = sum(vapply(x$expectations, testthat::expectation_error, logical(1))),
    duration = as.numeric(x$end_time - x$start_time, units = "secs")
  )
})
jsonlite::write_json(list(results = summ), json_file, pretty = TRUE, auto_unbox = TRUE)

# Coverage (best-effort)
if (requireNamespace("covr", quietly = TRUE)) {
  r_files <- list.files("R", pattern="\\.R$", full.names = TRUE)
  t_files <- list.files("tests/testthat", pattern="^test-.*\\.R$", full.names = TRUE)
  cov <- try(covr::file_coverage(r_files, t_files), silent = TRUE)
  if (!inherits(cov, "try-error")) {
    covr::report(cov, file = file.path(art, "coverage.html"), browse = FALSE)
  }
}
cat("\nArtifacts written to: ", normalizePath(art), "\n")

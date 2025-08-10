
test_that("antibiogram parser normalizes probabilities", {
  load_sources()
  td <- make_temp_dir()
  csv <- file.path(td, "abg.csv")
  write.csv(data.frame(drug=c("Meropenem","Meropenem"), mic=c(0.5,1), prob=c(0.7,0.7)), csv, row.names=FALSE)
  df <- read_antibiogram_csv(csv)
  ex <- dplyr::group_by(df, drug) |> dplyr::summarise(s=sum(prob), .groups="drop")
  expect_true(all(abs(ex$s-1) < 1e-6))
})

test_that("FHIR code param builder yields proper string", {
  load_sources()
  codes <- c("LOINC:1234-5","LOINC:2345-6")
  s <- .fhir_build_code_param(codes)
  expect_true(grepl("1234-5", s) && grepl("2345-6", s))
})

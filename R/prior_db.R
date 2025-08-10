# R/prior_db.R
# Priors als JSON je Wirkstoff laden/speichern
load_priors <- function(dir) {
  files <- list.files(dir, pattern = "\\.json$", full.names = TRUE)
  out <- list()
  for (f in files) {
    nm <- sub("\\.json$","", basename(f))
    out[[nm]] <- jsonlite::read_json(f, simplifyVector = TRUE)
  }
  out
}

save_prior <- function(dir, drug, prior_list) {
  dir.create(dir, showWarnings = FALSE, recursive = TRUE)
  jsonlite::write_json(prior_list, file.path(dir, paste0(drug, ".json")), auto_unbox = TRUE, pretty = TRUE)
}

# R/lis_ingest.R

read_tdm_csv <- function(path) {
  df <- readr::read_csv(path, show_col_types = FALSE, progress = FALSE)
  names(df) <- tolower(names(df))
  if ("datetime" %in% names(df) && !("time" %in% names(df))) df$time <- df$datetime
  if (!all(c("time","conc") %in% names(df))) stop("CSV benötigt mind. Spalten: time, conc")
  if (!is.numeric(df$time)) { tt <- as.POSIXct(df$time, tz = "UTC"); t0 <- min(tt, na.rm = TRUE); df$time <- as.numeric(difftime(tt, t0, units = "hours")) }
  if ("unit" %in% names(df) && any(nzchar(df$unit))) { fac <- vapply(df$unit, unit_factor, numeric(1)); df$conc <- df$conc * fac }
  df[, c("time","conc")]
}

read_mic_csv <- function(path) { read_antibiogram_csv(path) }
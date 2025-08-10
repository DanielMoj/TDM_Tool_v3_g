# R/loinc.R

load_loinc_map <- function(path = "config/loinc_map.json") {
  if (file.exists(path)) jsonlite::read_json(path, simplifyVector = TRUE) else list(tdm = list(), mic = list(), units = list())
}

unit_factor <- function(unit) {
  if (is.null(unit) || is.na(unit) || !nzchar(unit)) return(1)
  m <- c("mg/L" = 1, "ug/mL" = 1, "µg/mL" = 1, "mcg/mL" = 1, "mg/dL" = 10, "mcg/dL" = 0.1)
  m[[unit]] %||% 1
}
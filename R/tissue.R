# R/tissue.R
# Tissue/site penetration mapping

load_tissue_cfg <- function(path = "config/tissue.json") {
  if (file.exists(path)) jsonlite::read_json(path, simplifyVector = TRUE) else list()
}

site_factor <- function(drug, site, cfg) {
  if (is.null(cfg[[drug]])) return(cfg[["default"]][[site]] %||% 1.0)
  cfg[[drug]][[site]] %||% 1.0
}

apply_site_penetration <- function(conc_vec, drug, site, cfg) {
  f <- site_factor(drug, site, cfg)
  conc_vec * f
}

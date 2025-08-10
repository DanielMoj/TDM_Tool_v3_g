# R/targets.R
# Target library and utilities

load_targets_cfg <- function(path = "config/targets.json") {
  if (file.exists(path)) {
    jsonlite::read_json(path, simplifyVector = TRUE)
  } else {
    list()
  }
}

choose_target_for_drug <- function(drug, cfg) {
  # Simple mapping: exact drug or generic classes
  if (!is.null(cfg[[drug]])) return(cfg[[drug]])
  if (grepl("vanco", tolower(drug))) return(cfg[["Vancomycin"]])
  if (grepl("cillin|penem|cef|bactam", tolower(drug))) return(cfg[["Meropenem"]])
  if (grepl("amikacin|gentamicin|tobramycin|micin", tolower(drug))) return(cfg[["Aminoglycoside_Generic"]])
  NULL
}

# Check if given metrics satisfy the target
meets_target <- function(metrics, target) {
  if (is.null(target)) return(NA)
  m <- target$metric
  if (identical(m, "fT>MIC")) {
    return(isTRUE(metrics$ft_gt_mic >= (target$threshold %||% 0.5)))
  } else if (identical(m, "AUC24/MIC")) {
    thr_min <- target$threshold_min %||% 400
    thr_max <- target$threshold_max %||% Inf
    return(isTRUE(metrics$auc24_over_mic >= thr_min && metrics$auc24_over_mic <= thr_max))
  } else if (identical(m, "Cmax/MIC")) {
    thr <- target$threshold %||% 8
    return(isTRUE(metrics$cmax_over_mic >= thr))
  }
  NA
}

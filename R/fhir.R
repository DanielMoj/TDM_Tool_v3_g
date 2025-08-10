# R/fhir.R
requireNamespace("jsonlite", quietly = TRUE)

.fhir_build_code_param <- function(codes) paste(sprintf("http://loinc.org|%s", codes), collapse = ",")

fhir_get_observations <- function(base_url, patient_id, loinc_codes, token = NULL, since = NULL, per_page = 200) {
  if (!nzchar(base_url) || !nzchar(patient_id) || length(loinc_codes) == 0) stop("base_url, patient_id, loinc_codes erforderlich")
  code_param <- .fhir_build_code_param(loinc_codes)
  url <- sprintf("%s/Observation?patient=%s&code=%s&_count=%d", sub("/+$","",base_url), URLencode(patient_id), URLencode(code_param), per_page)
  if (!is.null(since) && nzchar(since)) url <- paste0(url, "&_lastUpdated=ge", URLencode(since))
  use_httr2 <- requireNamespace("httr2", quietly = TRUE)
  res_txt <- NULL
  if (use_httr2) {
    req <- httr2::request(url)
    if (!is.null(token) && nzchar(token)) req <- httr2::req_headers(req, Authorization = paste("Bearer", token))
    resp <- httr2::req_perform(req, path = NULL); httr2::resp_check_status(resp)
    res_txt <- httr2::resp_body_string(resp)
  } else {
    if (!requireNamespace("httr", quietly = TRUE)) stop("Bitte Paket 'httr2' oder 'httr' installieren.")
    h <- if (!is.null(token) && nzchar(token)) httr::add_headers(Authorization = paste("Bearer", token)) else NULL
    resp <- httr::GET(url, h); httr::stop_for_status(resp)
    res_txt <- httr::content(resp, as = "text", encoding = "UTF-8")
  }
  jsonlite::fromJSON(res_txt, simplifyVector = FALSE)
}

fhir_observations_to_tdm <- function(bundle_json, unit_map = NULL) {
  if (is.null(bundle_json$entry)) return(data.frame(time = numeric(0), conc = numeric(0), unit = character(0), code = character(0), time_h = numeric(0)))
  unit_map <- unit_map %||% c("mg/L" = 1, "ug/mL" = 1, "µg/mL" = 1, "mg/dL" = 10)
  rows <- list()
  for (e in bundle_json$entry) {
    r <- e$resource
    if (!identical(r$resourceType, "Observation")) next
    if (!is.null(r$valueQuantity)) {
      t <- r$effectiveDateTime %||% (if (!is.null(r$effectivePeriod)) r$effectivePeriod$start else NA_character_)
      val <- r$valueQuantity$value %||% NA_real_
      unit <- r$valueQuantity$unit %||% r$valueQuantity$code %||% ""
      fac <- unit_map[[unit]] %||% 1
      val_mgL <- as.numeric(val) * fac
      code <- if (!is.null(r$code$coding) && length(r$code$coding) > 0) r$code$coding[[1]]$code else NA_character_
      rows[[length(rows)+1]] <- data.frame(time = t, conc = val_mgL, unit = unit, code = code, stringsAsFactors = FALSE)
    }
  }
  if (length(rows) == 0) return(data.frame(time = numeric(0), conc = numeric(0), unit = character(0), code = character(0), time_h = numeric(0)))
  df <- do.call(rbind, rows)
  suppressWarnings({ tt <- as.POSIXct(df$time, tz = "UTC"); t0 <- min(tt, na.rm = TRUE); df$time_h <- as.numeric(difftime(tt, t0, units = "hours")) })
  df
}

# --- Pagination & Robust Fetch ---
fhir_fetch_all_pages <- function(url, token = NULL, max_pages = 20) {
  out <- list()
  next_url <- url
  for (i in seq_len(max_pages)) {
    use_httr2 <- requireNamespace("httr2", quietly = TRUE)
    res_txt <- NULL
    if (use_httr2) {
      req <- httr2::request(next_url)
      if (!is.null(token) && nzchar(token)) req <- httr2::req_headers(req, Authorization = paste("Bearer", token))
      resp <- httr2::req_perform(req, path = NULL)
      if (httr2::resp_status(resp) >= 400) break
      res_txt <- httr2::resp_body_string(resp)
    } else {
      if (!requireNamespace("httr", quietly = TRUE)) stop("Bitte Paket 'httr2' oder 'httr' installieren.")
      h <- if (!is.null(token) && nzchar(token)) httr::add_headers(Authorization = paste("Bearer", token)) else NULL
      resp <- httr::GET(next_url, h)
      if (httr::status_code(resp) >= 400) break
      res_txt <- httr::content(resp, as = "text", encoding = "UTF-8")
    }
    json <- jsonlite::fromJSON(res_txt, simplifyVector = FALSE)
    out[[length(out)+1]] <- json
    # Find next link
    lnks <- json$link
    nxt <- NULL
    if (!is.null(lnks)) {
      for (ln in lnks) {
        if (!is.null(ln$relation) && ln$relation == "next") { nxt <- ln$url; break }
      }
    }
    if (is.null(nxt) || !nzchar(nxt)) break
    next_url <- nxt
  }
  out
}

# Enhanced: get observations & flatten across pages
fhir_get_observations_all <- function(base_url, patient_id, loinc_codes, token = NULL, since = NULL, per_page = 200) {
  code_param <- .fhir_build_code_param(loinc_codes)
  url <- sprintf("%s/Observation?patient=%s&code=%s&_count=%d", sub("/+$","",base_url), URLencode(patient_id), URLencode(code_param), per_page)
  if (!is.null(since) && nzchar(since)) url <- paste0(url, "&_lastUpdated=ge", URLencode(since))
  bundles <- fhir_fetch_all_pages(url, token = token)
  # Merge entries
  entries <- list()
  for (b in bundles) if (!is.null(b$entry)) entries <- c(entries, b$entry)
  list(resourceType="Bundle", entry = entries)
}
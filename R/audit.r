# R/audit.R
# Audit logging with HMAC integrity and transactional DB writes
# SECURITY: Using HMAC for audit chain integrity

# Load required helpers
source(file.path("R", "db.R"), chdir = TRUE)

# Ensure audit file exists with proper structure
ensure_audit_file <- function(path) {
  if (!file.exists(path)) {
    dir.create(dirname(path), showWarnings = FALSE, recursive = TRUE)
    
    # Create initial structure
    df <- tibble::tibble(
      timestamp = character(),
      user = character(),
      role = character(),
      event = character(),
      details = character()
    )
    
    tryCatch({
      readr::write_csv(df, path)
      TRUE
    }, error = function(e) {
      warning("Could not create audit file: ", e$message)
      FALSE
    })
  } else {
    TRUE
  }
}

# Simple event logging (legacy format)
log_event <- function(path, user_info, event, details = list()) {
  if (!ensure_audit_file(path)) {
    warning("Audit logging failed - could not ensure file")
    return(invisible(FALSE))
  }
  
  # Extract user and role safely
  u <- tryCatch({
    if (is.function(user_info$user)) user_info$user() else user_info$user
  }, error = function(e) NULL)
  
  r <- tryCatch({
    if (is.function(user_info$role)) user_info$role() else user_info$role
  }, error = function(e) NULL)
  
  # Create audit record
  df <- tibble::tibble(
    timestamp = as.character(Sys.time()),
    user = u %||% "guest",
    role = r %||% "guest",
    event = event,
    details = jsonlite::toJSON(details, auto_unbox = TRUE)
  )
  
  # Append to file with error handling
  tryCatch({
    readr::write_csv(df, path, append = TRUE)
    TRUE
  }, error = function(e) {
    warning("Could not write to audit file: ", e$message)
    FALSE
  })
}

# --- Hash-chained Audit Log with HMAC ---

# Get HMAC key with validation
get_hmac_key <- function() {
  key <- Sys.getenv("AUDIT_HMAC_KEY", "")
  if (!nzchar(key)) {
    warning("AUDIT_HMAC_KEY not set - using default (INSECURE for production)")
    key <- "DEFAULT_HMAC_KEY_CHANGE_ME"
  }
  key
}

# SECURITY: Append to audit chain with HMAC integrity
audit_append_hashchain <- function(file = "log/audit.csv", actor, action, payload = list()) {
  if (!requireNamespace("digest", quietly = TRUE)) {
    stop("Package 'digest' required for audit chain")
  }
  
  # Get HMAC key
  hmac_key <- get_hmac_key()
  
  # Ensure directory exists
  dir.create(dirname(file), showWarnings = FALSE, recursive = TRUE)
  
  # Get previous hash
  prev_hash <- "GENESIS"
  if (file.exists(file)) {
    tb <- tryCatch({
      readr::read_csv(file, show_col_types = FALSE, progress = FALSE)
    }, error = function(e) NULL)
    
    if (!is.null(tb) && nrow(tb) > 0) {
      prev_hash <- tail(tb$hash, 1)
    }
  }
  
  # Create audit entry
  ts <- format(Sys.time(), tz = "UTC", usetz = TRUE)
  payload_json <- jsonlite::toJSON(payload, auto_unbox = TRUE, null = "null")
  chain_input <- paste(prev_hash, ts, actor, action, payload_json, sep = "|")
  
  # SECURITY: Use HMAC for integrity
  h <- digest::hmac(key = hmac_key, object = chain_input, algo = "sha256")
  
  # Create data frame
  df <- data.frame(
    ts = ts,
    actor = actor,
    action = action,
    payload = as.character(payload_json),
    prev_hash = prev_hash,
    hash = h,
    stringsAsFactors = FALSE
  )
  
  # Write to file with error handling
  result <- tryCatch({
    readr::write_csv(df, file, append = file.exists(file))
    TRUE
  }, error = function(e) {
    warning("Failed to write audit chain to file: ", e$message)
    FALSE
  })
  
  # Also write to DB if available (non-blocking)
  try(.audit_write_to_db(ts, actor, action, payload_json, prev_hash, h), silent = TRUE)
  
  invisible(h)
}

# SECURITY: Verify HMAC chain integrity
audit_verify_chain <- function(file = "log/audit.csv") {
  if (!requireNamespace("digest", quietly = TRUE)) {
    stop("Package 'digest' required for chain verification")
  }
  
  if (!file.exists(file)) {
    return(TRUE)  # Empty chain is valid
  }
  
  # Get HMAC key
  hmac_key <- get_hmac_key()
  
  # Read audit log
  tb <- tryCatch({
    readr::read_csv(file, show_col_types = FALSE, progress = FALSE)
  }, error = function(e) {
    warning("Could not read audit file: ", e$message)
    return(NULL)
  })
  
  if (is.null(tb) || nrow(tb) == 0) {
    return(TRUE)  # Empty chain is valid
  }
  
  # Verify each entry
  prev_hash <- "GENESIS"
  for (i in 1:nrow(tb)) {
    row <- tb[i,]
    chain_input <- paste(prev_hash, row$ts, row$actor, row$action, row$payload, sep = "|")
    
    # SECURITY: Verify using HMAC
    expected <- digest::hmac(key = hmac_key, object = chain_input, algo = "sha256")
    
    if (row$hash != expected) {
      warning(sprintf("Chain broken at row %d (ts: %s, action: %s)", 
                     i, row$ts, row$action))
      return(FALSE)
    }
    prev_hash <- row$hash
  }
  
  TRUE
}

# Write audit entry to database with transaction
.audit_write_to_db <- function(ts, actor, action, payload_json, prev_hash, hash) {
  # Use with_db_connection template with transaction
  with_db_connection({
    sql <- "INSERT INTO audit_log(ts, actor, action, payload, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6)"
    DBI::dbExecute(con, sql, params = list(
      ts,
      actor,
      action,
      as.character(payload_json),
      prev_hash,
      hash
    ))
    TRUE
  }, transactional = TRUE)  # Use transaction for atomicity
}

# Central audit event function with enhanced error handling
audit_event <- function(action, payload = list(), session = NULL, require_reason = FALSE) {
  # Validate reason if required
  if (require_reason && (is.null(payload$reason) || !nzchar(payload$reason))) {
    stop("This action requires a reason to be provided")
  }
  
  # Extract actor from session
  actor <- if (!is.null(session)) {
    tryCatch({
      session$userData$user()
    }, error = function(e) "guest")
  } else {
    "guest"
  }
  
  # Append to audit chain
  result <- tryCatch({
    audit_append_hashchain(
      actor = actor,
      action = action,
      payload = payload
    )
    TRUE
  }, error = function(e) {
    warning("Audit event failed: ", e$message)
    FALSE
  })
  
  invisible(result)
}

# Verify entire audit system integrity
audit_verify_system <- function(file = "log/audit.csv") {
  results <- list(
    file_exists = file.exists(file),
    chain_valid = FALSE,
    db_connected = FALSE,
    db_synced = FALSE,
    hmac_configured = nzchar(Sys.getenv("AUDIT_HMAC_KEY", ""))
  )
  
  # Check file chain
  if (results$file_exists) {
    results$chain_valid <- audit_verify_chain(file)
  }
  
  # Check DB connection
  results$db_connected <- db_test_connection()
  
  # Check DB sync (compare counts)
  if (results$db_connected && results$file_exists) {
    file_count <- tryCatch({
      tb <- readr::read_csv(file, show_col_types = FALSE, progress = FALSE)
      nrow(tb)
    }, error = function(e) 0)
    
    db_count <- with_db_connection({
      df <- DBI::dbGetQuery(con, "SELECT COUNT(*) as n FROM audit_log")
      df$n[1]
    })
    
    results$db_synced <- !is.null(db_count) && (abs(file_count - db_count) <= 1)
  }
  
  results
}

# Export audit log for analysis
audit_export <- function(file = "log/audit.csv", start_date = NULL, end_date = NULL, 
                        format = c("csv", "json")) {
  format <- match.arg(format)
  
  if (!file.exists(file)) {
    warning("No audit log to export")
    return(NULL)
  }
  
  # Read audit log
  tb <- tryCatch({
    readr::read_csv(file, show_col_types = FALSE, progress = FALSE)
  }, error = function(e) {
    warning("Could not read audit file: ", e$message)
    return(NULL)
  })
  
  if (is.null(tb) || nrow(tb) == 0) {
    return(NULL)
  }
  
  # Filter by date if specified
  if (!is.null(start_date) || !is.null(end_date)) {
    tb$ts_parsed <- as.POSIXct(tb$ts, tz = "UTC")
    
    if (!is.null(start_date)) {
      start_dt <- as.POSIXct(start_date, tz = "UTC")
      tb <- tb[tb$ts_parsed >= start_dt, ]
    }
    
    if (!is.null(end_date)) {
      end_dt <- as.POSIXct(end_date, tz = "UTC")
      tb <- tb[tb$ts_parsed <= end_dt, ]
    }
    
    tb$ts_parsed <- NULL
  }
  
  # Format output
  if (format == "json") {
    jsonlite::toJSON(tb, pretty = TRUE)
  } else {
    tb
  }
}

# Clean up old audit entries (with backup)
audit_cleanup <- function(file = "log/audit.csv", days_to_keep = 90, backup = TRUE) {
  if (!file.exists(file)) {
    return(invisible(0))
  }
  
  # Read audit log
  tb <- tryCatch({
    readr::read_csv(file, show_col_types = FALSE, progress = FALSE)
  }, error = function(e) {
    warning("Could not read audit file: ", e$message)
    return(NULL)
  })
  
  if (is.null(tb) || nrow(tb) == 0) {
    return(invisible(0))
  }
  
  # Parse timestamps
  tb$ts_parsed <- as.POSIXct(tb$ts, tz = "UTC")
  cutoff <- Sys.time() - (days_to_keep * 86400)
  
  # Split into keep and archive
  to_keep <- tb[tb$ts_parsed >= cutoff, ]
  to_archive <- tb[tb$ts_parsed < cutoff, ]
  
  if (nrow(to_archive) == 0) {
    message("No audit entries to clean up")
    return(invisible(0))
  }
  
  # Create backup if requested
  if (backup && nrow(to_archive) > 0) {
    backup_file <- sprintf("%s.archive_%s.csv", 
                          tools::file_path_sans_ext(file),
                          format(Sys.time(), "%Y%m%d_%H%M%S"))
    
    tryCatch({
      readr::write_csv(to_archive, backup_file)
      message(sprintf("Archived %d entries to %s", nrow(to_archive), backup_file))
    }, error = function(e) {
      warning("Could not create backup: ", e$message)
      return(invisible(0))
    })
  }
  
  # Rewrite audit file with remaining entries
  to_keep$ts_parsed <- NULL
  
  tryCatch({
    readr::write_csv(to_keep, file, append = FALSE)
    message(sprintf("Cleaned up %d old audit entries", nrow(to_archive)))
    nrow(to_archive)
  }, error = function(e) {
    warning("Could not update audit file: ", e$message)
    0
  })
}
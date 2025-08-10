# R/db.R
# Lightweight DB helpers for Postgres with security hardening and standardized error handling
# SECURITY: All SQL queries use parameterized statements to prevent SQL injection

# Template function for safe DB operations with automatic connection management
with_db_connection <- function(expr, transactional = FALSE) {
  con <- NULL
  result <- NULL
  tryCatch({
    con <- connect_pg()
    if (inherits(con, "try-error") || is.null(con)) {
      warning("Database connection failed - operation skipped")
      return(NULL)
    }
    
    # Start transaction if requested
    if (transactional) {
      DBI::dbBegin(con)
    }
    
    # Execute the expression with the connection
    result <- eval(substitute(expr), envir = parent.frame())
    
    # Commit transaction if started
    if (transactional) {
      DBI::dbCommit(con)
    }
    
    result
  }, error = function(e) {
    # Rollback transaction on error
    if (transactional && !is.null(con) && !inherits(con, "try-error")) {
      try(DBI::dbRollback(con), silent = TRUE)
    }
    warning("Database operation failed: ", e$message)
    NULL
  }, finally = {
    # Always ensure connection is closed
    if (!is.null(con) && !inherits(con, "try-error")) {
      try(DBI::dbDisconnect(con), silent = TRUE)
    }
  })
}

# Connection helper with proper error handling
connect_pg <- function() {
  # Check for required packages
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) {
    warning("DB packages missing (DBI, RPostgres)")
    return(NULL)
  }
  
  # Try DSN first
  dsn <- Sys.getenv("PG_DSN", "")
  if (nzchar(dsn)) {
    con <- tryCatch(
      DBI::dbConnect(RPostgres::Postgres(), dsn = dsn),
      error = function(e) {
        warning("DSN connection failed: ", e$message)
        NULL
      }
    )
    if (!is.null(con)) return(con)
  }
  
  # Fall back to individual parameters
  host <- Sys.getenv("PGHOST", "localhost")
  port <- as.integer(Sys.getenv("PGPORT", "5432"))
  db   <- Sys.getenv("PGDATABASE", "tdmx")
  user <- Sys.getenv("PGUSER", "tdmx")
  pass <- Sys.getenv("PGPASSWORD", "")
  
  tryCatch(
    DBI::dbConnect(RPostgres::Postgres(), 
                   host = host, port = port, dbname = db, 
                   user = user, password = pass),
    error = function(e) {
      warning("DB connection failed: ", e$message)
      NULL
    }
  )
}

# SECURITY: Fixed SQL injection - uses parameterized query
db_write_audit <- function(user, role, event, details = list()) {
  with_db_connection({
    sql <- "INSERT INTO audit_log(user_name, role, event, details) VALUES($1,$2,$3,$4::jsonb)"
    DBI::dbExecute(con, sql, params = list(
      user %||% "guest", 
      role %||% "guest", 
      event, 
      jsonlite::toJSON(details, auto_unbox = TRUE)
    ))
    TRUE
  })
}

# SECURITY: Fixed SQL injection - uses parameterized query
db_write_dataset_version <- function(kind, version, checksum, meta = list()) {
  stopifnot(!is.null(kind), !is.null(version), !is.null(checksum))
  
  with_db_connection({
    sql <- "INSERT INTO dataset_versions(kind, version, checksum, meta) VALUES ($1,$2,$3,$4)"
    DBI::dbExecute(con, sql, params = list(
      kind, 
      version, 
      checksum, 
      jsonlite::toJSON(meta, auto_unbox = TRUE)
    ))
    TRUE
  }, transactional = TRUE)
}

# SECURITY: Fixed SQL injection - dbWriteTable handles parameterization internally
db_import_antibiogram <- function(df, source = "upload", version = NULL) {
  stopifnot(all(c("drug","mic","prob") %in% colnames(df)))
  
  # Check for digest package
  if (!requireNamespace("digest", quietly = TRUE)) {
    stop("Package 'digest' required for checksums")
  }
  
  with_db_connection({
    # Normalize per drug (ensure sum(prob)=1)
    df <- dplyr::group_by(df, drug) |> 
          dplyr::mutate(prob = prob / sum(prob)) |> 
          dplyr::ungroup()
    
    # Add source column
    df$source <- source
    
    # Insert rows - dbWriteTable handles parameterization internally
    DBI::dbWriteTable(con, "antibiogram", df, append = TRUE, row.names = FALSE)
    
    # Version entry
    v <- version %||% format(Sys.time(), "%Y%m%d%H%M%S")
    checksum <- digest::digest(df, algo = "sha256")
    meta <- list(
      source = source, 
      rows = nrow(df), 
      drugs = length(unique(df$drug))
    )
    
    # Write version record
    sql <- "INSERT INTO dataset_versions(kind, version, checksum, meta) VALUES ($1,$2,$3,$4)"
    DBI::dbExecute(con, sql, params = list(
      "antibiogram",
      v,
      checksum,
      jsonlite::toJSON(meta, auto_unbox = TRUE)
    ))
    
    message(sprintf("Imported %d antibiogram rows for %d drugs", nrow(df), meta$drugs))
    list(version = v, checksum = checksum, rows = nrow(df))
  }, transactional = TRUE)  # Use transaction for atomicity
}

# SECURITY: Fixed SQL injection - uses parameterized query
db_get_antibiogram <- function(drug = NULL) {
  with_db_connection({
    if (is.null(drug)) {
      df <- DBI::dbGetQuery(con, "SELECT * FROM antibiogram ORDER BY drug, mic")
    } else {
      # SECURITY: Parameterized query prevents SQL injection
      sql <- "SELECT * FROM antibiogram WHERE drug = $1 ORDER BY mic"
      df <- DBI::dbGetQuery(con, sql, params = list(drug))
    }
    df
  })
}

# List available drugs in antibiogram
db_list_antibiogram_drugs <- function() {
  with_db_connection({
    df <- DBI::dbGetQuery(con, "SELECT DISTINCT drug FROM antibiogram ORDER BY drug")
    if (!is.null(df) && nrow(df) > 0) df$drug else character(0)
  })
}

# Get latest dataset version
db_get_latest_version <- function(kind) {
  with_db_connection({
    sql <- "SELECT * FROM dataset_versions WHERE kind = $1 ORDER BY created_at DESC LIMIT 1"
    df <- DBI::dbGetQuery(con, sql, params = list(kind))
    if (nrow(df) > 0) df[1,] else NULL
  })
}

# Check if antibiogram data exists
db_has_antibiogram_data <- function() {
  with_db_connection({
    df <- DBI::dbGetQuery(con, "SELECT COUNT(*) as n FROM antibiogram")
    !is.null(df) && df$n[1] > 0
  })
}

# Clean up old antibiogram data (keep only latest version per drug)
db_cleanup_antibiogram <- function() {
  with_db_connection({
    # Get latest version
    latest <- DBI::dbGetQuery(con, 
      "SELECT MAX(created_at) as latest FROM antibiogram"
    )
    
    if (!is.null(latest) && !is.na(latest$latest[1])) {
      # Delete older entries (keep last 24 hours)
      cutoff <- as.POSIXct(latest$latest[1]) - 86400  # 24 hours
      sql <- "DELETE FROM antibiogram WHERE created_at < $1"
      deleted <- DBI::dbExecute(con, sql, params = list(cutoff))
      message(sprintf("Cleaned up %d old antibiogram entries", deleted))
      deleted
    } else {
      0
    }
  }, transactional = TRUE)
}

# Helper function for testing DB connection
db_test_connection <- function() {
  con <- connect_pg()
  if (is.null(con) || inherits(con, "try-error")) {
    return(FALSE)
  }
  
  # Try a simple query
  result <- tryCatch({
    DBI::dbGetQuery(con, "SELECT 1 as test")
    TRUE
  }, error = function(e) {
    FALSE
  }, finally = {
    try(DBI::dbDisconnect(con), silent = TRUE)
  })
  
  result
}
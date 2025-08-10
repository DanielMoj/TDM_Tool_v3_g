# R/utils.R
# Zentrale Utility-Funktionen mit Fehlerbehandlung

# Null-Coalescing Operator - erweiterte Version für alle Fälle
`%||%` <- function(a, b) {
  if (is.null(a) || length(a) == 0 ||
      (is.character(a) && !nzchar(a)) ||
      all(is.na(a))) b else a
}

# Parse numeric list from comma-separated string
parse_num_list <- function(x) {
  if (is.null(x) || is.na(x) || !nzchar(x)) {
    return(numeric(0))
  }
  
  # Split and clean
  parts <- trimws(unlist(strsplit(x, ",")))
  
  # Convert to numeric with warning for failures
  vals <- suppressWarnings(as.numeric(parts))
  
  # Check for conversion failures
  failed <- is.na(vals) & nzchar(parts)
  if (any(failed)) {
    warning(sprintf("Could not parse %d value(s): %s", 
                   sum(failed), 
                   paste(parts[failed], collapse = ", ")))
  }
  
  # Return valid values
  vals[!is.na(vals)]
}

# Stop with NA check
stop_na <- function(x, msg) {
  if (any(!is.finite(x))) {
    stop(msg, call. = FALSE)
  }
  invisible(x)
}

# Generate lognormal random values
rnorm_log <- function(mu, sd, n = 1) {
  if (n <= 0) stop("n must be positive")
  if (sd < 0) stop("sd must be non-negative")
  exp(rnorm(n, mean = mu, sd = sd))
}

# Calculate median and IQR
median_iqr <- function(x) {
  x <- x[is.finite(x)]
  if (length(x) == 0) {
    return(c(median = NA_real_, IQR = NA_real_))
  }
  c(median = stats::median(x), IQR = IQR(x))
}

# Safe file path construction
safe_file_path <- function(...) {
  parts <- list(...)
  # Remove empty parts
  parts <- parts[nzchar(parts)]
  # Construct path
  do.call(file.path, parts)
}

# Check if a package is available
check_package <- function(pkg, stop_if_missing = FALSE) {
  available <- requireNamespace(pkg, quietly = TRUE)
  if (!available && stop_if_missing) {
    stop(sprintf("Required package '%s' is not installed", pkg))
  }
  available
}

# Safe numeric conversion with default
as_numeric_safe <- function(x, default = NA_real_) {
  result <- suppressWarnings(as.numeric(x))
  ifelse(is.na(result), default, result)
}

# Format time difference for display
format_time_diff <- function(start, end = Sys.time()) {
  diff <- difftime(end, start, units = "secs")
  secs <- as.numeric(diff)
  
  if (secs < 60) {
    sprintf("%.1f seconds", secs)
  } else if (secs < 3600) {
    sprintf("%.1f minutes", secs / 60)
  } else if (secs < 86400) {
    sprintf("%.1f hours", secs / 3600)
  } else {
    sprintf("%.1f days", secs / 86400)
  }
}

# Create temporary directory with cleanup
with_temp_dir <- function(expr, prefix = "tdmx_") {
  temp_dir <- tempfile(pattern = prefix, tmpdir = tempdir())
  dir.create(temp_dir, recursive = TRUE)
  
  # Ensure cleanup on exit
  on.exit({
    if (dir.exists(temp_dir)) {
      unlink(temp_dir, recursive = TRUE)
    }
  }, add = TRUE)
  
  # Execute expression with temp_dir available
  eval(substitute(expr), envir = list(temp_dir = temp_dir), enclos = parent.frame())
}

# Retry function with exponential backoff
retry_with_backoff <- function(expr, max_attempts = 3, initial_wait = 1) {
  attempt <- 1
  wait_time <- initial_wait
  
  while (attempt <= max_attempts) {
    result <- tryCatch({
      list(success = TRUE, value = expr)
    }, error = function(e) {
      list(success = FALSE, error = e)
    })
    
    if (result$success) {
      return(result$value)
    }
    
    if (attempt < max_attempts) {
      message(sprintf("Attempt %d failed, retrying in %.1f seconds...", 
                     attempt, wait_time))
      Sys.sleep(wait_time)
      wait_time <- wait_time * 2  # Exponential backoff
    }
    
    attempt <- attempt + 1
  }
  
  # All attempts failed
  stop(sprintf("All %d attempts failed. Last error: %s", 
              max_attempts, result$error$message))
}

# Validate email format
is_valid_email <- function(email) {
  if (!is.character(email) || length(email) != 1) {
    return(FALSE)
  }
  grepl("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", email)
}

# Sanitize filename
sanitize_filename <- function(name, replacement = "_") {
  # Remove or replace invalid characters
  gsub("[^A-Za-z0-9._-]", replacement, name)
}

# Check if running in Shiny
is_shiny <- function() {
  !is.null(shiny::getDefaultReactiveDomain())
}

# Safe JSON parsing
parse_json_safe <- function(json_str, default = list()) {
  if (!is.character(json_str) || !nzchar(json_str)) {
    return(default)
  }
  
  tryCatch({
    jsonlite::fromJSON(json_str, simplifyVector = TRUE)
  }, error = function(e) {
    warning("JSON parsing failed: ", e$message)
    default
  })
}

# Format number for display with significant digits
format_number <- function(x, digits = 3) {
  if (!is.numeric(x)) return(as.character(x))
  
  # Handle special cases
  if (is.na(x)) return("NA")
  if (is.infinite(x)) return(ifelse(x > 0, "Inf", "-Inf"))
  
  # Format based on magnitude
  if (abs(x) >= 1000 || abs(x) < 0.001) {
    format(x, scientific = TRUE, digits = digits)
  } else {
    format(round(x, digits), nsmall = min(digits, 3))
  }
}

# Create a hash of an R object (for caching)
object_hash <- function(obj) {
  if (!requireNamespace("digest", quietly = TRUE)) {
    stop("Package 'digest' required for hashing")
  }
  digest::digest(obj, algo = "xxhash64")
}

# Check if a value is "empty" (NULL, NA, empty string, etc.)
is_empty <- function(x) {
  is.null(x) || 
  length(x) == 0 || 
  all(is.na(x)) ||
  (is.character(x) && all(!nzchar(x)))
}

# Ensure a value is within bounds
clamp <- function(x, lower = -Inf, upper = Inf) {
  pmax(lower, pmin(upper, x))
}

# Create a progress message
progress_message <- function(current, total, prefix = "Progress") {
  pct <- round(100 * current / total)
  sprintf("%s: %d/%d (%d%%)", prefix, current, total, pct)
}
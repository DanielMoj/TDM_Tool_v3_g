# R/antibiogram.R
# Antibiogram data handling with standardized error management

# Load required helpers
source(file.path("R", "db.R"), chdir = TRUE)

# Read and normalize antibiogram CSV
read_antibiogram_csv <- function(path) {
  # Input validation
  if (!file.exists(path)) {
    stop("File not found: ", path)
  }
  
  # Read CSV with error handling
  df <- tryCatch({
    readr::read_csv(path, show_col_types = FALSE, progress = FALSE)
  }, error = function(e) {
    stop("Failed to read CSV: ", e$message)
  })
  
  # Check required columns
  req_cols <- c("drug", "mic", "prob")
  miss <- setdiff(req_cols, names(df))
  if (length(miss) > 0) {
    stop("Missing required columns: ", paste(miss, collapse = ", "))
  }
  
  # Type conversion and validation
  df$drug <- as.character(df$drug)
  df$mic <- as.numeric(df$mic)
  df$prob <- as.numeric(df$prob)
  
  # Filter invalid rows
  valid <- is.finite(df$mic) & is.finite(df$prob) & df$prob >= 0
  if (sum(!valid) > 0) {
    warning(sprintf("Removed %d invalid rows", sum(!valid)))
  }
  df <- df[valid, ]
  
  # Normalize probabilities per drug
  if (!requireNamespace("dplyr", quietly = TRUE)) {
    stop("Package 'dplyr' required for data normalization")
  }
  
  df <- dplyr::group_by(df, drug) |> 
        dplyr::mutate(prob = prob / sum(prob)) |> 
        dplyr::ungroup()
  
  # Return normalized data
  as.data.frame(df)
}

# Convert antibiogram data to text format for UI
antibiogram_to_text <- function(df, drug) {
  if (!is.data.frame(df) || nrow(df) == 0) {
    return("")
  }
  
  sub <- df[df$drug == drug, ]
  if (nrow(sub) == 0) {
    return("")
  }
  
  # Sort by MIC
  sub <- sub[order(sub$mic), ]
  
  # Format as "mic:prob" pairs
  paste(sprintf("%g:%0.3f", sub$mic, sub$prob), collapse = ", ")
}

# ---- DB Bridge Functions with Error Handling ----

# Import antibiogram data to database
antibiogram_import_to_db <- function(path, source = "upload", version = NULL) {
  # Validate input file
  if (!file.exists(path)) {
    stop("Import file not found: ", path)
  }
  
  # Read and normalize CSV
  df <- tryCatch({
    read_antibiogram_csv(path)
  }, error = function(e) {
    stop("Failed to read antibiogram CSV: ", e$message)
  })
  
  if (nrow(df) == 0) {
    warning("No valid data to import")
    return(NULL)
  }
  
  # Import to database using template
  result <- db_import_antibiogram(df, source = source, version = version)
  
  if (is.null(result)) {
    warning("Database import failed - check connection and logs")
    return(NULL)
  }
  
  message(sprintf("Successfully imported antibiogram data: %d rows", result$rows))
  result
}

# Get list of drugs from database
antibiogram_drugs_db <- function() {
  # Use template function for safe DB access
  drugs <- db_list_antibiogram_drugs()
  
  if (is.null(drugs)) {
    warning("Could not retrieve drug list from database")
    return(character(0))
  }
  
  drugs
}

# Get antibiogram data for a specific drug
antibiogram_from_db <- function(drug) {
  if (!is.character(drug) || !nzchar(drug)) {
    stop("Valid drug name required")
  }
  
  # Use template function for safe DB access
  df <- db_get_antibiogram(drug)
  
  if (is.null(df)) {
    warning(sprintf("Could not retrieve antibiogram data for drug: %s", drug))
    return(data.frame(drug = character(0), mic = numeric(0), prob = numeric(0)))
  }
  
  # Ensure probabilities sum to 1
  if (nrow(df) > 0) {
    total_prob <- sum(df$prob)
    if (abs(total_prob - 1) > 0.01) {
      warning(sprintf("Probabilities for %s sum to %.3f, normalizing", drug, total_prob))
      df$prob <- df$prob / total_prob
    }
  }
  
  df
}

# Get all antibiogram data from database
antibiogram_all_from_db <- function() {
  # Use template function for safe DB access
  df <- db_get_antibiogram(NULL)
  
  if (is.null(df)) {
    warning("Could not retrieve antibiogram data from database")
    return(data.frame(drug = character(0), mic = numeric(0), prob = numeric(0)))
  }
  
  df
}

# Check if antibiogram data exists in database
antibiogram_exists_db <- function() {
  result <- db_has_antibiogram_data()
  isTRUE(result)
}

# Get latest version info for antibiogram data
antibiogram_version_info <- function() {
  info <- db_get_latest_version("antibiogram")
  
  if (is.null(info)) {
    return(list(
      has_data = FALSE,
      version = NA_character_,
      updated = NA_character_,
      rows = 0
    ))
  }
  
  list(
    has_data = TRUE,
    version = info$version,
    updated = format(info$created_at, "%Y-%m-%d %H:%M:%S"),
    rows = info$meta$rows %||% 0,
    drugs = info$meta$drugs %||% 0
  )
}

# Clean up old antibiogram entries
antibiogram_cleanup <- function() {
  result <- db_cleanup_antibiogram()
  
  if (is.null(result)) {
    warning("Could not clean up antibiogram data")
    return(0)
  }
  
  result
}

# Parse MIC distribution text (UI input format)
parse_mic_distribution <- function(txt) {
  # Handle empty input
  if (is.null(txt) || !nzchar(txt)) {
    return(NULL)
  }
  
  # Split by comma
  parts <- trimws(unlist(strsplit(txt, ",")))
  
  # Parse each "mic:prob" pair
  vals <- lapply(parts, function(p) {
    kv <- trimws(unlist(strsplit(p, ":")))
    if (length(kv) != 2) {
      warning(sprintf("Invalid MIC:prob pair: %s", p))
      return(c(NA, NA))
    }
    c(as.numeric(kv[1]), as.numeric(kv[2]))
  })
  
  # Convert to matrix
  if (length(vals) == 0) return(NULL)
  vals <- do.call(rbind, vals)
  
  # Create data frame
  df <- data.frame(
    mic = vals[,1],
    prob = vals[,2]
  )
  
  # Filter valid entries
  valid <- is.finite(df$mic) & is.finite(df$prob) & df$prob >= 0
  df <- df[valid, , drop = FALSE]
  
  if (nrow(df) == 0) return(NULL)
  
  # Normalize probabilities
  df$prob <- df$prob / sum(df$prob)
  
  df
}

# Validate antibiogram data structure
validate_antibiogram <- function(df) {
  if (!is.data.frame(df)) {
    return(list(valid = FALSE, message = "Not a data frame"))
  }
  
  # Check required columns
  req_cols <- c("drug", "mic", "prob")
  if (!all(req_cols %in% names(df))) {
    return(list(valid = FALSE, message = "Missing required columns"))
  }
  
  # Check data types
  if (!is.character(df$drug) && !is.factor(df$drug)) {
    return(list(valid = FALSE, message = "Drug column must be character or factor"))
  }
  
  if (!is.numeric(df$mic)) {
    return(list(valid = FALSE, message = "MIC column must be numeric"))
  }
  
  if (!is.numeric(df$prob)) {
    return(list(valid = FALSE, message = "Probability column must be numeric"))
  }
  
  # Check for valid values
  if (any(df$mic <= 0, na.rm = TRUE)) {
    return(list(valid = FALSE, message = "MIC values must be positive"))
  }
  
  if (any(df$prob < 0 | df$prob > 1, na.rm = TRUE)) {
    return(list(valid = FALSE, message = "Probabilities must be between 0 and 1"))
  }
  
  # Check probability sums per drug
  if (requireNamespace("dplyr", quietly = TRUE)) {
    sums <- dplyr::group_by(df, drug) |>
            dplyr::summarise(total = sum(prob), .groups = "drop")
    
    off <- abs(sums$total - 1) > 0.01
    if (any(off)) {
      drugs <- sums$drug[off]
      return(list(
        valid = FALSE, 
        message = sprintf("Probabilities don't sum to 1 for: %s", 
                         paste(drugs, collapse = ", "))
      ))
    }
  }
  
  list(valid = TRUE, message = "Valid antibiogram data")
}
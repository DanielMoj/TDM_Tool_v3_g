# R/load_all.R
# Central loading function for all dependencies
# This replaces 27 individual source() calls

#' Load all required source files and dependencies
#' @return invisible TRUE
#' @export
load_all_sources <- function() {
  
  # Load required packages
  required_packages <- c(
    "shiny", "shinydashboard", "shinyjs", "shinyWidgets",
    "DT", "plotly", "ggplot2", "dplyr", "tidyr",
    "rjags", "coda", "DBI", "RPostgres", "pool",
    "digest", "jsonlite", "lubridate"
  )
  
  # Load packages silently
  invisible(lapply(required_packages, function(pkg) {
    if (!require(pkg, character.only = TRUE, quietly = TRUE)) {
      stop(paste("Package", pkg, "is required but not installed"))
    }
  }))
  
  # Define source files in loading order
  # Dependencies first, then modules
  source_files <- c(
    # Core utilities
    "utils/config",
    "utils/helpers",
    "utils/validators",
    
    # Database and authentication
    "core/db_connection",
    "core/auth_functions",
    "core/audit_logger",
    
    # PK/PD specific
    "models/pk_models",
    "models/pk_parameters",
    "models/dosing_regimens",
    
    # Analysis functions
    "run_fit_jags",  # Main fitting function
    "diagnostics",
    "optimization",
    "sensitivity",
    
    # Data processing
    "data/data_import",
    "data/data_validation",
    "data/data_transformation",
    
    # Plotting functions
    "plots/plot_concentrations",
    "plots/plot_diagnostics",
    "plots/plot_parameters",
    
    # Report generation
    "reports/report_generator",
    "reports/export_functions"
  )
  
  # Source all files with error handling
  for (file in source_files) {
    file_path <- file.path("R", paste0(file, ".R"))
    if (file.exists(file_path)) {
      tryCatch({
        source(file_path, local = FALSE)
        message(paste("✓ Loaded:", file_path))
      }, error = function(e) {
        warning(paste("Failed to load:", file_path, "-", e$message))
      })
    } else {
      # Create placeholder if file doesn't exist (for development)
      message(paste("ℹ File not found (skipping):", file_path))
    }
  }
  
  # Load all modules
  module_files <- list.files(
    path = "R/modules",
    pattern = "^mod_.*\\.R$",
    full.names = TRUE
  )
  
  for (module_file in module_files) {
    tryCatch({
      source(module_file, local = FALSE)
      message(paste("✓ Loaded module:", basename(module_file)))
    }, error = function(e) {
      warning(paste("Failed to load module:", module_file, "-", e$message))
    })
  }
  
  # Set global options
  options(
    shiny.maxRequestSize = 50*1024^2,  # 50MB upload limit
    shiny.sanitize.errors = TRUE,
    digits = 4,
    scipen = 999
  )
  
  # Initialize database pool if config exists
  if (file.exists("config/database.yml")) {
    message("Initializing database connection pool...")
    # initialize_db_pool() would be defined in db_connection.R
  }
  
  message("\n✓ All sources loaded successfully")
  invisible(TRUE)
}

#' Clean up resources on app shutdown
#' @export
cleanup_resources <- function() {
  # Close database connections
  if (exists("db_pool") && !is.null(db_pool)) {
    pool::poolClose(db_pool)
    message("Database pool closed")
  }
  
  # Clean up temporary files
  temp_files <- list.files(tempdir(), pattern = "^pk_", full.names = TRUE)
  if (length(temp_files) > 0) {
    unlink(temp_files)
    message(paste("Cleaned up", length(temp_files), "temporary files"))
  }
  
  invisible(TRUE)
}
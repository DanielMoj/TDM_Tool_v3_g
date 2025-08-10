# tests/testthat/test-db-error-handling.R
# Test suite for standardized DB error handling

library(testthat)

# Source required files
source(file.path("R", "utils.R"))
source(file.path("R", "db.R"))
source(file.path("R", "antibiogram.R"))
source(file.path("R", "audit.R"))

context("Database Error Handling")

# --- Test DB Connection Template ---
test_that("with_db_connection handles connection failures gracefully", {
  # Save original environment
  original_dsn <- Sys.getenv("PG_DSN")
  original_host <- Sys.getenv("PGHOST")
  
  # Set invalid connection parameters
  Sys.setenv(PG_DSN = "")
  Sys.setenv(PGHOST = "invalid_host_12345")
  
  # Test that operation returns NULL on connection failure
  result <- with_db_connection({
    data.frame(test = 1)
  })
  
  expect_null(result)
  
  # Restore original environment
  Sys.setenv(PG_DSN = original_dsn)
  Sys.setenv(PGHOST = original_host)
})

test_that("with_db_connection closes connections on error", {
  skip_if_not(db_test_connection(), "Database not available")
  
  # Track if connection is closed
  connection_closed <- FALSE
  
  # Mock DBI::dbDisconnect to track calls
  with_mock(
    `DBI::dbDisconnect` = function(con) {
      connection_closed <<- TRUE
      TRUE
    },
    {
      # Force an error within the connection block
      result <- with_db_connection({
        stop("Test error")
      })
      
      expect_null(result)
      expect_true(connection_closed)
    }
  )
})

test_that("with_db_connection handles transactions correctly", {
  skip_if_not(db_test_connection(), "Database not available")
  
  # Test successful transaction
  result <- with_db_connection({
    # This should succeed
    TRUE
  }, transactional = TRUE)
  
  expect_true(result)
  
  # Test failed transaction with rollback
  result <- with_db_connection({
    # Force an error
    stop("Transaction test error")
  }, transactional = TRUE)
  
  expect_null(result)
})

# --- Test Antibiogram Functions ---
test_that("antibiogram functions handle missing database gracefully", {
  # Save original environment
  original_dsn <- Sys.getenv("PG_DSN")
  original_host <- Sys.getenv("PGHOST")
  
  # Disable database
  Sys.setenv(PG_DSN = "")
  Sys.setenv(PGHOST = "")
  
  # Test that functions return appropriate defaults
  drugs <- antibiogram_drugs_db()
  expect_equal(drugs, character(0))
  
  data <- antibiogram_from_db("TestDrug")
  expect_equal(nrow(data), 0)
  expect_true(all(c("drug", "mic", "prob") %in% names(data)))
  
  exists <- antibiogram_exists_db()
  expect_false(exists)
  
  # Restore original environment
  Sys.setenv(PG_DSN = original_dsn)
  Sys.setenv(PGHOST = original_host)
})

test_that("antibiogram CSV validation works correctly", {
  # Create temporary test file
  temp_file <- tempfile(fileext = ".csv")
  
  # Test with valid data
  valid_data <- data.frame(
    drug = c("DrugA", "DrugA", "DrugB"),
    mic = c(0.5, 1.0, 2.0),
    prob = c(0.3, 0.7, 1.0)
  )
  write.csv(valid_data, temp_file, row.names = FALSE)
  
  df <- read_antibiogram_csv(temp_file)
  expect_equal(nrow(df), 3)
  expect_true(all(abs(tapply(df$prob, df$drug, sum) - 1) < 0.01))
  
  # Test with invalid data (missing column)
  invalid_data <- data.frame(
    drug = c("DrugA", "DrugA"),
    mic = c(0.5, 1.0)
  )
  write.csv(invalid_data, temp_file, row.names = FALSE)
  
  expect_error(read_antibiogram_csv(temp_file), "Missing required columns")
  
  # Test with non-existent file
  expect_error(read_antibiogram_csv("nonexistent.csv"), "File not found")
  
  # Clean up
  unlink(temp_file)
})

test_that("antibiogram probability normalization works", {
  temp_file <- tempfile(fileext = ".csv")
  
  # Create data with non-normalized probabilities
  data <- data.frame(
    drug = c("DrugA", "DrugA", "DrugA"),
    mic = c(0.5, 1.0, 2.0),
    prob = c(1, 2, 3)  # Sum = 6, not 1
  )
  write.csv(data, temp_file, row.names = FALSE)
  
  df <- read_antibiogram_csv(temp_file)
  
  # Check that probabilities are normalized
  drug_a_probs <- df$prob[df$drug == "DrugA"]
  expect_equal(sum(drug_a_probs), 1.0, tolerance = 0.001)
  
  # Check relative proportions are maintained
  expect_equal(drug_a_probs[2] / drug_a_probs[1], 2, tolerance = 0.001)
  expect_equal(drug_a_probs[3] / drug_a_probs[1], 3, tolerance = 0.001)
  
  unlink(temp_file)
})

# --- Test Audit Functions ---
test_that("audit chain integrity verification works", {
  # Create temporary audit file
  temp_audit <- tempfile(fileext = ".csv")
  
  # Set HMAC key for testing
  Sys.setenv(AUDIT_HMAC_KEY = "test-key-12345")
  
  # Write some entries
  audit_append_hashchain(
    file = temp_audit,
    actor = "test_user",
    action = "test_action_1",
    payload = list(data = "test1")
  )
  
  audit_append_hashchain(
    file = temp_audit,
    actor = "test_user",
    action = "test_action_2",
    payload = list(data = "test2")
  )
  
  # Verify chain is valid
  expect_true(audit_verify_chain(temp_audit))
  
  # Tamper with the file
  audit_data <- readr::read_csv(temp_audit, show_col_types = FALSE)
  audit_data$action[1] <- "tampered_action"
  readr::write_csv(audit_data, temp_audit)
  
  # Verification should now fail
  expect_false(audit_verify_chain(temp_audit))
  
  # Clean up
  unlink(temp_audit)
  Sys.unsetenv("AUDIT_HMAC_KEY")
})

test_that("audit system verification reports correct status", {
  temp_audit <- tempfile(fileext = ".csv")
  
  # Set HMAC key
  Sys.setenv(AUDIT_HMAC_KEY = "test-key-verify")
  
  # Write an entry
  audit_append_hashchain(
    file = temp_audit,
    actor = "test",
    action = "verify_test",
    payload = list()
  )
  
  # Run system verification
  status <- audit_verify_system(temp_audit)
  
  expect_true(status$file_exists)
  expect_true(status$chain_valid)
  expect_true(status$hmac_configured)
  
  # Clean up
  unlink(temp_audit)
  Sys.unsetenv("AUDIT_HMAC_KEY")
})

test_that("audit cleanup preserves recent entries", {
  temp_audit <- tempfile(fileext = ".csv")
  
  Sys.setenv(AUDIT_HMAC_KEY = "test-cleanup")
  
  # Create old and new entries
  for (i in 1:5) {
    # Manually create entries with old timestamps
    ts <- format(Sys.time() - (100 * 86400), tz = "UTC", usetz = TRUE)  # 100 days ago
    df <- data.frame(
      ts = ts,
      actor = "old_user",
      action = paste0("old_action_", i),
      payload = "{}",
      prev_hash = "TEST",
      hash = paste0("HASH", i),
      stringsAsFactors = FALSE
    )
    
    if (i == 1) {
      readr::write_csv(df, temp_audit, append = FALSE)
    } else {
      readr::write_csv(df, temp_audit, append = TRUE)
    }
  }
  
  # Add recent entries
  audit_append_hashchain(
    file = temp_audit,
    actor = "recent_user",
    action = "recent_action",
    payload = list()
  )
  
  # Run cleanup (keep last 30 days)
  cleaned <- audit_cleanup(temp_audit, days_to_keep = 30, backup = FALSE)
  
  # Check that old entries were removed
  expect_equal(cleaned, 5)
  
  # Verify recent entry remains
  remaining <- readr::read_csv(temp_audit, show_col_types = FALSE)
  expect_true(any(grepl("recent_action", remaining$action)))
  expect_false(any(grepl("old_action", remaining$action)))
  
  # Clean up
  unlink(temp_audit)
  Sys.unsetenv("AUDIT_HMAC_KEY")
})

# --- Test Connection Helper ---
test_that("connect_pg returns NULL on failure with warning", {
  # Save original environment
  original_dsn <- Sys.getenv("PG_DSN")
  original_host <- Sys.getenv("PGHOST")
  
  # Set invalid parameters
  Sys.setenv(PG_DSN = "postgresql://invalid:invalid@nonexistent:5432/none")
  Sys.setenv(PGHOST = "nonexistent_host_99999")
  
  # Should return NULL and warn
  expect_warning(con <- connect_pg())
  expect_null(con)
  
  # Restore
  Sys.setenv(PG_DSN = original_dsn)
  Sys.setenv(PGHOST = original_host)
})

test_that("db_test_connection returns boolean", {
  result <- db_test_connection()
  expect_type(result, "logical")
  expect_length(result, 1)
})

# --- Test Parse MIC Distribution ---
test_that("parse_mic_distribution handles various inputs", {
  # Valid input
  result <- parse_mic_distribution("0.5:0.3, 1:0.5, 2:0.2")
  expect_equal(nrow(result), 3)
  expect_equal(sum(result$prob), 1.0, tolerance = 0.001)
  
  # Empty input
  expect_null(parse_mic_distribution(""))
  expect_null(parse_mic_distribution(NULL))
  
  # Invalid format
  expect_warning(result <- parse_mic_distribution("0.5:0.3, invalid, 2:0.2"))
  expect_equal(nrow(result), 2)
  
  # Non-normalized probabilities
  result <- parse_mic_distribution("1:1, 2:2, 4:1")
  expect_equal(sum(result$prob), 1.0, tolerance = 0.001)
  expect_equal(result$prob[2], 0.5, tolerance = 0.001)
})
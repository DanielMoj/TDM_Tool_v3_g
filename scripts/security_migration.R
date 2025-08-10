#!/usr/bin/env Rscript
# scripts/security_migration.R
# Migration script for security hardening
# Run this ONCE to migrate existing systems to the new security model

cat("=== TDMx Security Migration Script ===\n")
cat("This script will:\n")
cat("1. Check environment variables\n")
cat("2. Migrate plaintext passwords to hashes\n")
cat("3. Verify audit chain integrity\n")
cat("4. Test authentication\n\n")

# Load required functions
source("R/auth.R")
source("R/audit.R")

# --- Step 1: Check Environment Variables ---
cat("Step 1: Checking environment variables...\n")

check_env <- function(var_name, required = TRUE) {
  val <- Sys.getenv(var_name, "")
  if (nzchar(val)) {
    cat(sprintf("  ✓ %s is set\n", var_name))
    return(TRUE)
  } else if (required) {
    cat(sprintf("  ✗ %s is NOT set (REQUIRED)\n", var_name))
    return(FALSE)
  } else {
    cat(sprintf("  ⚠ %s is not set (optional)\n", var_name))
    return(TRUE)
  }
}

env_ok <- TRUE
env_ok <- check_env("AUDIT_HMAC_KEY", required = TRUE) && env_ok

if (!env_ok) {
  cat("\n❌ Missing required environment variables!\n")
  cat("Generate AUDIT_HMAC_KEY with: openssl rand -hex 32\n")
  cat("Add to your .env file or export in shell\n")
  stop("Cannot proceed without required environment variables")
}

check_env("PGHOST", required = FALSE)
check_env("PGDATABASE", required = FALSE)
check_env("TDMX_JWT_SECRET", required = FALSE)

# --- Step 2: Migrate Passwords ---
cat("\nStep 2: Migrating passwords to hashes...\n")

users_file <- "config/users.yaml"
if (file.exists(users_file)) {
  cat(sprintf("  Found users file: %s\n", users_file))
  
  # Load current configuration
  users <- credentials_load(users_file)
  
  # Check for plaintext passwords
  has_plaintext <- FALSE
  has_hashes <- FALSE
  
  for (usr in users$users) {
    if (!is.null(usr$password)) {
      has_plaintext <- TRUE
      cat(sprintf("  ⚠ User '%s' has plaintext password\n", usr$username))
    }
    if (!is.null(usr$password_hash)) {
      has_hashes <- TRUE
      cat(sprintf("  ✓ User '%s' has password hash\n", usr$username))
    }
  }
  
  if (has_plaintext) {
    cat("\n  Plaintext passwords detected. Migrating...\n")
    
    # Ask for confirmation
    response <- readline("  Migrate plaintext passwords to hashes? (y/n): ")
    
    if (tolower(response) == "y") {
      # Perform migration
      if (auth_upgrade_hashes(users_file, backup = TRUE)) {
        cat("  ✓ Passwords migrated successfully\n")
        cat(sprintf("  Backup saved as: %s.bak\n", users_file))
      } else {
        cat("  No migration needed\n")
      }
    } else {
      cat("  Migration skipped\n")
    }
  } else if (has_hashes) {
    cat("  ✓ All users already have hashed passwords\n")
  } else {
    cat("  No users found in configuration\n")
  }
} else {
  cat(sprintf("  Users file not found: %s\n", users_file))
  cat("  Please create the file with user configurations\n")
}

# --- Step 3: Verify Audit Chain ---
cat("\nStep 3: Checking audit chain integrity...\n")

audit_file <- "log/audit.csv"
if (file.exists(audit_file)) {
  cat(sprintf("  Found audit log: %s\n", audit_file))
  
  # Check if file has content
  audit_data <- readr::read_csv(audit_file, show_col_types = FALSE)
  
  if (nrow(audit_data) > 0) {
    cat(sprintf("  Audit log contains %d entries\n", nrow(audit_data)))
    
    # Verify chain
    if (audit_verify_chain(audit_file)) {
      cat("  ✓ Audit chain integrity verified\n")
    } else {
      cat("  ✗ Audit chain integrity check failed\n")
      cat("  This is expected if migrating from non-HMAC to HMAC\n")
      
      # Offer to archive old log and start fresh
      archive_file <- paste0(audit_file, ".", format(Sys.time(), "%Y%m%d_%H%M%S"), ".archive")
      
      response <- readline("  Archive old audit log and start fresh? (y/n): ")
      if (tolower(response) == "y") {
        file.rename(audit_file, archive_file)
        cat(sprintf("  Archived to: %s\n", archive_file))
        
        # Create first HMAC-protected entry
        audit_append_hashchain(
          file = audit_file,
          actor = "system",
          action = "security_migration",
          payload = list(
            timestamp = Sys.time(),
            old_audit_archived = archive_file,
            hmac_enabled = TRUE
          )
        )
        cat("  ✓ New HMAC-protected audit chain started\n")
      }
    }
  } else {
    cat("  Audit log is empty\n")
  }
} else {
  cat("  No existing audit log found\n")
  cat("  Creating new HMAC-protected audit chain...\n")
  
  # Create first entry
  audit_append_hashchain(
    file = audit_file,
    actor = "system",
    action = "security_migration",
    payload = list(
      timestamp = Sys.time(),
      hmac_enabled = TRUE,
      migration_run = TRUE
    )
  )
  cat("  ✓ New HMAC-protected audit chain created\n")
}

# --- Step 4: Test Authentication ---
cat("\nStep 4: Testing authentication system...\n")

if (file.exists(users_file)) {
  users <- credentials_load(users_file)
  
  if (length(users$users) > 0) {
    test_user <- users$users[[1]]
    
    cat(sprintf("  Testing with user: %s\n", test_user$username))
    
    # Test that plaintext passwords are rejected
    if (!is.null(test_user$password)) {
      # This should fail after migration
      result <- auth_check(test_user$username, test_user$password)
      if (result) {
        cat("  ✗ SECURITY ISSUE: Plaintext password still accepted!\n")
        stop("Security migration failed - plaintext passwords still work")
      } else {
        cat("  ✓ Plaintext password correctly rejected\n")
      }
    }
    
    # Test with a known password (only works if you know it)
    cat("\n  To test login, run:\n")
    cat('  auth_check("username", "your-password")\n')
    cat("  This should return TRUE if the password is correct\n")
  }
} else {
  cat("  No users file found - skipping auth test\n")
}

# --- Summary ---
cat("\n=== Migration Summary ===\n")
cat("✓ Environment variables checked\n")

if (file.exists(users_file)) {
  users <- credentials_load(users_file)
  n_users <- length(users$users)
  n_hashed <- sum(sapply(users$users, function(u) !is.null(u$password_hash)))
  cat(sprintf("✓ Password migration: %d/%d users have hashed passwords\n", n_hashed, n_users))
}

if (file.exists(audit_file)) {
  if (audit_verify_chain(audit_file)) {
    cat("✓ Audit chain uses HMAC integrity protection\n")
  } else {
    cat("⚠ Audit chain needs attention (see above)\n")
  }
}

cat("\n=== Next Steps ===\n")
cat("1. Ensure AUDIT_HMAC_KEY is set in production environment\n")
cat("2. Test user logins with their original passwords\n")
cat("3. Monitor audit logs for any issues\n")
cat("4. Remove any backup files after confirming system works\n")
cat("5. Document the HMAC key securely (password manager)\n")
cat("\n✅ Security migration complete!\n")
# Database Error Handling Standards

## Overview
This document describes the standardized error handling patterns for database operations in the TDMx system.

## Core Template Function

### `with_db_connection(expr, transactional = FALSE)`

The central template function for all database operations that ensures:
- Automatic connection management
- Proper resource cleanup
- Transaction support
- Consistent error handling

#### Usage Examples

**Simple query:**
```r
result <- with_db_connection({
  DBI::dbGetQuery(con, "SELECT * FROM antibiogram")
})
```

**Transactional operation:**
```r
result <- with_db_connection({
  # Multiple operations as atomic unit
  DBI::dbExecute(con, "INSERT INTO table1 ...")
  DBI::dbExecute(con, "UPDATE table2 ...")
  TRUE
}, transactional = TRUE)
```

## Error Handling Patterns

### 1. Connection Failures
- Returns `NULL` when database is unavailable
- Logs warning with connection error details
- Allows application to continue with degraded functionality

### 2. Query Failures
- Operations within `with_db_connection` return `NULL` on error
- Transactions are automatically rolled back
- Error details are logged as warnings

### 3. Resource Management
- Connections are **always** closed, even on error
- Uses `finally` block to ensure cleanup
- No connection leaks possible

## Function Categories

### Critical Operations (Use Transactions)
These operations modify data and should be atomic:
- `db_import_antibiogram()` - Imports with version tracking
- `db_write_dataset_version()` - Version metadata
- `audit_write_to_db()` - Audit log entries
- `db_cleanup_antibiogram()` - Data cleanup

### Read Operations (No Transaction Needed)
Simple queries that don't modify data:
- `db_get_antibiogram()` - Fetch MIC distributions
- `db_list_antibiogram_drugs()` - List available drugs
- `db_get_latest_version()` - Get version info
- `db_has_antibiogram_data()` - Check data existence

## Best Practices

### 1. Always Use the Template
```r
# ✅ GOOD - Uses template
db_get_data <- function() {
  with_db_connection({
    DBI::dbGetQuery(con, "SELECT * FROM table")
  })
}

# ❌ BAD - Manual connection management
db_get_data <- function() {
  con <- connect_pg()
  data <- DBI::dbGetQuery(con, "SELECT * FROM table")
  DBI::dbDisconnect(con)
  data
}
```

### 2. Handle NULL Returns
```r
# All DB functions can return NULL
data <- db_get_antibiogram("Drug")
if (is.null(data)) {
  warning("Could not fetch data from database")
  # Use fallback or default
  data <- default_antibiogram_data()
}
```

### 3. Use Transactions for Multi-Step Operations
```r
import_complex_data <- function(data) {
  with_db_connection({
    # Step 1: Clear old data
    DBI::dbExecute(con, "DELETE FROM table WHERE ...")
    
    # Step 2: Insert new data
    DBI::dbWriteTable(con, "table", data, append = TRUE)
    
    # Step 3: Update metadata
    DBI::dbExecute(con, "UPDATE metadata SET ...")
    
    TRUE  # Return success
  }, transactional = TRUE)  # All-or-nothing
}
```

### 4. Parameterized Queries Only
```r
# ✅ GOOD - Parameterized (SQL injection safe)
with_db_connection({
  sql <- "SELECT * FROM table WHERE drug = $1"
  DBI::dbGetQuery(con, sql, params = list(drug_name))
})

# ❌ BAD - String concatenation (SQL injection risk)
with_db_connection({
  sql <- paste0("SELECT * FROM table WHERE drug = '", drug_name, "'")
  DBI::dbGetQuery(con, sql)
})
```

## Error Recovery Strategies

### 1. Graceful Degradation
When database is unavailable, functions return sensible defaults:
- Empty data frames with correct structure
- Empty character vectors for lists
- `FALSE` for existence checks
- `NULL` for complex objects

### 2. Retry Logic
For critical operations, consider retry with backoff:
```r
result <- retry_with_backoff({
  db_import_antibiogram(data)
}, max_attempts = 3, initial_wait = 1)
```

### 3. Audit Trail
All database errors are logged to:
- Console warnings (immediate visibility)
- Audit log (if available)
- Application logs (if configured)

## Testing

### Unit Tests
Located in `tests/testthat/test-db-error-handling.R`:
- Connection failure scenarios
- Transaction rollback verification
- Resource cleanup validation
- NULL return handling

### Integration Tests
Test with actual database:
```r
# Check if DB is available
if (db_test_connection()) {
  # Run integration tests
  test_antibiogram_import()
  test_audit_chain()
}
```

## Migration Guide

### Converting Legacy Functions

**Before:**
```r
old_function <- function() {
  con <- DBI::dbConnect(...)
  result <- DBI::dbGetQuery(con, "SELECT ...")
  DBI::dbDisconnect(con)
  result
}
```

**After:**
```r
new_function <- function() {
  with_db_connection({
    DBI::dbGetQuery(con, "SELECT ...")
  })
}
```

## Troubleshooting

### Common Issues

1. **"Database connection failed" warnings**
   - Check environment variables: `PG_DSN`, `PGHOST`, `PGPORT`, etc.
   - Verify database is running
   - Check network connectivity

2. **Transactions not working**
   - Ensure `transactional = TRUE` is set
   - Check that all operations use same connection (`con`)
   - Verify database supports transactions

3. **Resource leaks**
   - Always use `with_db_connection` template
   - Never store connection objects globally
   - Check for errors in `finally` blocks

## Environment Variables

Required for database connection:
```bash
# Option 1: DSN (preferred)
PG_DSN="postgresql://user:pass@host:5432/dbname"

# Option 2: Individual parameters
PGHOST="localhost"
PGPORT="5432"
PGDATABASE="tdmx"
PGUSER="tdmx"
PGPASSWORD="secure_password"
```

## Security Considerations

1. **SQL Injection Prevention**
   - All queries use parameterization
   - No string concatenation for SQL
   - Input validation before queries

2. **Connection Security**
   - Credentials from environment only
   - No hardcoded passwords
   - SSL/TLS when available

3. **Audit Trail**
   - All DB operations logged
   - HMAC integrity for audit chain
   - Transaction atomicity for critical ops
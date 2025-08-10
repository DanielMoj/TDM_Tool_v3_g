# Security Fixes Applied

## Overview
This document describes the security improvements made to the TDMx TDM system to address critical vulnerabilities.

## 1. SQL Injection Prevention (R/db.R)

### Problem
Direct SQL queries without parameterization could allow SQL injection attacks.

### Solution
- **All SQL queries now use parameterized statements** via `DBI::dbExecute()` and `DBI::dbGetQuery()` with `params` parameter
- Functions affected and fixed:
  - ✅ `db_write_audit()` - Uses parameterized query
  - ✅ `db_write_dataset_version()` - Uses parameterized query
  - ✅ `db_import_antibiogram()` - Uses `dbWriteTable()` which handles parameterization
  - ✅ `db_get_antibiogram()` - Uses parameterized query
  - ✅ `.aud_db_write()` - Uses parameterized query

### Verification
```bash
# This should return no results:
grep -r "paste.*WHERE\|sprintf.*SELECT\|paste.*INSERT\|sprintf.*UPDATE" R/
```

## 2. Plaintext Password Removal (R/auth.R)

### Problem
The system had a fallback mechanism that allowed plaintext passwords, creating a severe security vulnerability.

### Solution
- **Removed all plaintext password fallback code** (lines 25-27 in original)
- Functions fixed:
  - ✅ `auth_check()` - Now ONLY accepts hashed passwords
  - ✅ `auth_esign_verify()` - Plaintext fallback removed
- Only `password_verify()` with sodium/argon2 hashes is now accepted
- Use `auth_upgrade_hashes()` to migrate existing plaintext passwords to hashes

### Migration Path
```r
# One-time migration to convert plaintext passwords to hashes:
auth_upgrade_hashes("config/users.yaml", backup = TRUE)
```

## 3. Audit Chain Integrity with HMAC (R/audit.R)

### Problem
Audit logs used simple SHA256 hashing without a secret key, allowing potential tampering.

### Solution
- **Replaced `digest::digest()` with `digest::hmac()`** using a secret key
- Functions fixed:
  - ✅ `audit_append_hashchain()` - Now uses HMAC with secret key
  - ✅ `audit_verify_chain()` - Verifies using HMAC
  - ✅ `.aud_db_write()` - DB audit also uses HMAC

### Configuration Required
```bash
# Set the HMAC key in your environment:
export AUDIT_HMAC_KEY="your-secret-hmac-key-here"

# Generate a strong key:
openssl rand -hex 32
```

## Environment Variables

### Required for Security
```bash
# Audit integrity
AUDIT_HMAC_KEY="<generated-secret-key>"

# Database (if using)
PGHOST="localhost"
PGPORT="5432"
PGDATABASE="tdmx"
PGUSER="tdmx"
PGPASSWORD="<secure-password>"

# API Authentication (if using API)
TDMX_JWT_SECRET="<generated-jwt-secret>"
```

## Testing Security Fixes

### 1. SQL Injection Test
```r
# This should fail safely with error, not execute malicious SQL:
drug_name <- "'; DROP TABLE antibiogram; --"
db_get_antibiogram(con, drug_name)  # Should handle safely
```

### 2. Password Test
```r
# This should return FALSE (no plaintext accepted):
auth_check("admin", "admin123")  # FALSE unless password is hashed

# Correct usage:
hash <- password_hash("admin123")
# Store hash in users.yaml, then:
auth_check("admin", "admin123")  # TRUE if hash matches
```

### 3. Audit Chain Test
```r
# Set HMAC key first
Sys.setenv(AUDIT_HMAC_KEY = "test-key-123")

# Write some audit entries
audit_append_hashchain(actor = "test", action = "test1", payload = list(a = 1))
audit_append_hashchain(actor = "test", action = "test2", payload = list(b = 2))

# Verify chain integrity
audit_verify_chain()  # Should return TRUE

# Tamper with file manually, then:
audit_verify_chain()  # Should return FALSE
```

## Acceptance Criteria Met

✅ **SQL Injection Prevention**
- No direct string concatenation in SQL queries
- All queries use parameterized statements

✅ **No Plaintext Passwords**
- `auth_check()` rejects plaintext passwords
- Only sodium/argon2 hashed passwords accepted
- Migration path provided for existing systems

✅ **Audit Chain Integrity**
- HMAC with secret key protects audit trail
- New environment variable `AUDIT_HMAC_KEY` required
- Tampering is detectable via `audit_verify_chain()`

## Recommendations

1. **Immediately set `AUDIT_HMAC_KEY`** in production environment
2. **Run `auth_upgrade_hashes()`** to convert any plaintext passwords
3. **Remove plaintext passwords** from `config/users.yaml` after migration
4. **Rotate HMAC and JWT keys** regularly (quarterly recommended)
5. **Monitor audit logs** for failed authentication attempts
6. **Use strong passwords** and consider implementing 2FA in future

## Migration Steps

1. **Set environment variable:**
   ```bash
   export AUDIT_HMAC_KEY=$(openssl rand -hex 32)
   ```

2. **Run migration script:**
   ```r
   source("scripts/security_migration.R")
   ```

3. **Test authentication:**
   ```r
   source("tests/testthat/test-security.R")
   ```

4. **Verify acceptance criteria:**
   ```bash
   # Should return nothing:
   grep -r "paste.*WHERE\|sprintf.*SELECT" R/
   ```

## Compliance

These security fixes help meet common compliance requirements:
- **HIPAA**: Audit controls, access controls, integrity controls
- **GDPR**: Data protection by design, integrity and confidentiality
- **FDA 21 CFR Part 11**: Audit trails, access controls, electronic signatures

## Support

For questions about these security improvements, please contact the security team or file an issue in the project repository.
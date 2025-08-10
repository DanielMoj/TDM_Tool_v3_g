# .env.example - Security-hardened environment configuration
# Copy to .env and fill with your actual values

# === SECURITY CRITICAL - MUST SET ===
# Generate with: openssl rand -hex 32
AUDIT_HMAC_KEY="CHANGE_ME_USE_OPENSSL_RAND_HEX_32"

# === Database Configuration ===
# PostgreSQL connection
PG_DSN="postgresql://tdmx:tdmx@localhost:5432/tdmx"
PGHOST="localhost"
PGPORT="5432"
PGDATABASE="tdmx"
PGUSER="tdmx"
PGPASSWORD="CHANGE_ME_USE_STRONG_PASSWORD"

# === API Security ===
# JWT Secret for API authentication
# Generate with: openssl rand -hex 32
TDMX_JWT_SECRET="CHANGE_ME_USE_OPENSSL_RAND_HEX_32"

# === Application Settings ===
# Audit log path
TDMX_AUDIT_PATH="audit/audit_log.csv"

# Cache directory
TDMX_CACHE_DIR="cache/"

# Stan MCMC defaults
TDMX_STAN_CHAINS="4"
TDMX_STAN_ITER="1000"

# === FHIR Integration (Optional) ===
# FHIR server for EHR integration
FHIR_BASE_URL=""
FHIR_BEARER_TOKEN=""

# === Security Notes ===
# 1. NEVER commit this file with real values to version control
# 2. Use strong, unique passwords (min 16 chars, mixed case, numbers, symbols)
# 3. Rotate AUDIT_HMAC_KEY and TDMX_JWT_SECRET quarterly
# 4. Monitor audit logs for suspicious activity
# 5. Ensure file permissions: chmod 600 .env
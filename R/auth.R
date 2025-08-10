# R/auth.R (hardened)
# Uses libsodium for password hashing (argon2) and verifies stored hashes.
# SECURITY: Removed all plaintext password fallbacks - only hash-based authentication allowed

credentials_load <- function(path = "config/users.yaml") {
  if (!file.exists(path)) stop("users.yaml fehlt")
  if (!requireNamespace("yaml", quietly = TRUE)) stop("Bitte Paket 'yaml' installieren.")
  yaml::read_yaml(path)
}

password_hash <- function(p) {
  if (!requireNamespace("sodium", quietly = TRUE)) stop("Bitte Paket 'sodium' installieren.")
  sodium::password_store(charToRaw(p))
}

password_verify <- function(p, hash) {
  if (!requireNamespace("sodium", quietly = TRUE)) stop("Bitte Paket 'sodium' installieren.")
  tryCatch(sodium::password_verify(hash, charToRaw(p)), error = function(e) FALSE)
}

# SECURITY: Fixed - Removed plaintext password fallback (lines 25-27)
auth_check <- function(username, password, path = "config/users.yaml") {
  users <- credentials_load(path)
  if (is.null(users$users)) stop("users.yaml: Abschnitt 'users' fehlt")
  u <- NULL
  for (usr in users$users) if (identical(usr$username, username)) { u <- usr; break }
  if (is.null(u)) return(FALSE)
  # SECURITY: Only accept hashed passwords, no plaintext fallback
  if (!is.null(u$password_hash)) {
    return(isTRUE(password_verify(password, u$password_hash)))
  }
  # SECURITY: Removed plaintext password check - force hash usage
  return(FALSE)
}

# ---- Session Management ----
auth_set_user <- function(session, username, role) {
  if (!requireNamespace("shiny", quietly = TRUE)) return(invisible(FALSE))
  session$userData$user <- reactiveVal(username)
  session$userData$role <- reactiveVal(role)
  invisible(TRUE)
}

# Utility: upgrade users.yaml by hashing plaintext passwords (one-time action)
auth_upgrade_hashes <- function(path = "config/users.yaml", backup = TRUE) {
  if (!requireNamespace("yaml", quietly = TRUE)) stop("Bitte Paket 'yaml' installieren.")
  users <- credentials_load(path)
  changed <- FALSE
  for (i in seq_along(users$users)) {
    u <- users$users[[i]]
    if (!is.null(u$password) && is.null(u$password_hash)) {
      u$password_hash <- as.character(password_hash(u$password))
      u$password <- NULL
      users$users[[i]] <- u; changed <- TRUE
    }
  }
  if (changed) {
    if (backup) file.copy(path, paste0(path, ".bak"), overwrite = TRUE)
    yaml::write_yaml(users, path)
  }
  invisible(changed)
}

# ---- Roles & Policies ----
policies_load <- function(path = "config/policies.yaml") {
  if (!requireNamespace("yaml", quietly = TRUE)) stop("Bitte Paket 'yaml' installieren.")
  yaml::read_yaml(path)
}

policy_allow <- function(role, action, policies = NULL) {
  if (is.null(policies)) policies <- policies_load()
  if (is.null(policies$policies)) stop("policies.yaml: Abschnitt 'policies' fehlt")
  for (p in policies$policies) {
    if (identical(p$role, role) && action %in% p$actions) return(TRUE)
  }
  FALSE
}

# ---- E-Sign Verification ----
# SECURITY: Fixed - Removed plaintext password fallback in esign
auth_esign_verify <- function(session, password) {
  if (!requireNamespace("shiny", quietly = TRUE)) stop("Bitte Paket 'shiny' installieren.")
  username <- tryCatch(session$userData$user(), error = function(e) NULL)
  if (is.null(username)) return(FALSE)
  users <- credentials_load()
  u <- NULL
  for (usr in users$users) if (identical(usr$username, username)) { u <- usr; break }
  if (is.null(u)) return(FALSE)
  # SECURITY: Only accept hashed passwords for e-signature
  if (!is.null(u$password_hash)) {
    return(isTRUE(password_verify(password, u$password_hash)))
  }
  return(FALSE)
}

# api/plumber_auth.R
# Token-basierte Authentifizierung für Plumber-API (HMAC/JWT via 'jose')

#* @apiTitle Auth
#* @apiDescription Token-Ausgabe & Filter

#* Token ausstellen
#* @param username
#* @param password
#* @post /auth/token
function(username, password, res) {
  ok <- try(auth_check(username, password), silent = TRUE)
  if (!isTRUE(ok)) { res$status <- 401; return(list(error="invalid_credentials")) }
  secret <- Sys.getenv("TDMX_JWT_SECRET", "CHANGE_ME")
  if (!requireNamespace("jose", quietly = TRUE)) { res$status <- 500; return(list(error="missing_jose_package")) }
  claims <- list(sub = username, iat = as.numeric(Sys.time()), exp = as.numeric(Sys.time()) + 3600)
  token <- jose::jwt_encode_hmac(claims, secret = charToRaw(secret))
  list(access_token = token, token_type = "Bearer", expires_in = 3600)
}

#* @filter bearerAuth
function(req, res) {
  path <- req$PATH_INFO %||% ""
  # Allow auth endpoint without token
  if (startsWith(path, "/auth/token")) { return(forward()) }
  auth <- req$HTTP_AUTHORIZATION %||% ""
  if (!nzchar(auth)) { res$status <- 401; return(list(error = "missing_authorization")) }
  # Expect "Bearer <token>"
  parts <- strsplit(auth, " ")[[1]]
  if (length(parts) != 2 || tolower(parts[1]) != "bearer") { res$status <- 401; return(list(error = "invalid_authorization_header")) }
  token <- parts[2]
  secret <- Sys.getenv("TDMX_JWT_SECRET", "CHANGE_ME")
  if (!requireNamespace("jose", quietly = TRUE)) { res$status <- 500; return(list(error="missing_jose_package")) }
  ok <- TRUE
  claims <- NULL
  tryCatch({
    claims <<- jose::jwt_decode_hmac(token, secret = charToRaw(secret))
  }, error = function(e) ok <<- FALSE)
  if (!ok) { res$status <- 401; return(list(error="invalid_token")) }
  # Attach user to request for handlers
  req$user <- claims$sub
  forward()
}

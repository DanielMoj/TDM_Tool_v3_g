# R/modules/mod_auth.R
# Authentication Module for Shiny App

#' Authentication Module UI
#' @param id Module ID
#' @return Shiny UI elements
#' @export
mod_auth_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    shinyjs::useShinyjs(),
    div(
      id = ns("auth_panel"),
      class = "login-panel",
      tags$head(
        tags$style(HTML("
          .login-panel {
            max-width: 400px;
            margin: 100px auto;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          .login-title {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
          }
        "))
      ),
      
      h2("PK/PD Analysis Platform", class = "login-title"),
      
      wellPanel(
        textInput(
          ns("username"),
          label = "Username",
          placeholder = "Enter your username",
          width = "100%"
        ),
        
        passwordInput(
          ns("password"),
          label = "Password",
          placeholder = "Enter your password",
          width = "100%"
        ),
        
        div(
          style = "margin-top: 20px;",
          actionButton(
            ns("login"),
            "Login",
            class = "btn-primary",
            width = "100%"
          )
        ),
        
        div(
          id = ns("auth_message"),
          style = "margin-top: 15px; text-align: center;",
          textOutput(ns("login_error"))
        )
      ),
      
      div(
        style = "text-align: center; margin-top: 20px; color: #666;",
        tags$small("Version 2.0 - Modularized")
      )
    )
  )
}

#' Authentication Module Server
#' @param id Module ID
#' @param config App configuration object
#' @return Reactive values with authentication state
#' @export
mod_auth_server <- function(id, config = NULL) {
  moduleServer(id, function(input, output, session) {
    
    # Initialize authentication state
    auth_state <- reactiveValues(
      logged_in = FALSE,
      user = NULL,
      role = NULL,
      login_time = NULL,
      session_id = NULL
    )
    
    # Login handler
    observeEvent(input$login, {
      req(input$username, input$password)
      
      # Show loading state
      shinyjs::disable("login")
      
      # Validate credentials
      validation_result <- validate_credentials(
        username = input$username,
        password = input$password,
        config = config
      )
      
      if (validation_result$success) {
        # Update auth state
        auth_state$logged_in <- TRUE
        auth_state$user <- validation_result$user
        auth_state$role <- validation_result$role
        auth_state$login_time <- Sys.time()
        auth_state$session_id <- generate_session_id()
        
        # Log successful login
        log_audit_event(
          event_type = "LOGIN_SUCCESS",
          user = validation_result$user,
          details = list(
            ip = session$request$HTTP_X_FORWARDED_FOR %||% session$request$REMOTE_ADDR,
            user_agent = session$request$HTTP_USER_AGENT
          )
        )
        
        # Clear error message
        output$login_error <- renderText("")
        
        # Hide login panel
        shinyjs::hide("auth_panel", anim = TRUE, animType = "fade")
        
      } else {
        # Log failed login attempt
        log_audit_event(
          event_type = "LOGIN_FAILED",
          user = input$username,
          details = list(
            reason = validation_result$message
          )
        )
        
        # Show error message
        output$login_error <- renderText({
          validation_result$message
        })
        
        # Re-enable login button
        shinyjs::enable("login")
      }
    })
    
    # Logout handler
    logout <- function() {
      if (auth_state$logged_in) {
        log_audit_event(
          event_type = "LOGOUT",
          user = auth_state$user,
          details = list(
            session_duration = difftime(Sys.time(), auth_state$login_time, units = "mins")
          )
        )
        
        # Reset auth state
        auth_state$logged_in <- FALSE
        auth_state$user <- NULL
        auth_state$role <- NULL
        auth_state$login_time <- NULL
        auth_state$session_id <- NULL
        
        # Show login panel again
        shinyjs::show("auth_panel", anim = TRUE, animType = "fade")
      }
    }
    
    # Session timeout (30 minutes)
    observe({
      if (auth_state$logged_in) {
        invalidateLater(30 * 60 * 1000)  # Check every 30 minutes
        
        if (difftime(Sys.time(), auth_state$login_time, units = "mins") > 30) {
          showNotification(
            "Session expired. Please login again.",
            type = "warning",
            duration = 5
          )
          logout()
        }
      }
    })
    
    # Return authentication state and methods
    return(list(
      state = reactive(auth_state),
      logout = logout,
      is_logged_in = reactive(auth_state$logged_in),
      get_user = reactive(auth_state$user),
      get_role = reactive(auth_state$role),
      has_permission = function(permission) {
        check_permission(auth_state$role, permission)
      }
    ))
  })
}

# Helper functions (would normally be in auth_functions.R)

#' Validate user credentials
#' @param username Username
#' @param password Password
#' @param config Configuration object
#' @return List with validation result
validate_credentials <- function(username, password, config = NULL) {
  # This would normally check against database
  # For demo purposes, using simple validation
  
  if (username == "" || password == "") {
    return(list(
      success = FALSE,
      message = "Username and password are required"
    ))
  }
  
  # Demo users (would be in database)
  valid_users <- list(
    admin = list(password = digest::digest("admin123"), role = "admin"),
    user = list(password = digest::digest("user123"), role = "user"),
    analyst = list(password = digest::digest("analyst123"), role = "analyst")
  )
  
  if (!username %in% names(valid_users)) {
    return(list(
      success = FALSE,
      message = "Invalid username or password"
    ))
  }
  
  hashed_password <- digest::digest(password)
  
  if (valid_users[[username]]$password != hashed_password) {
    return(list(
      success = FALSE,
      message = "Invalid username or password"
    ))
  }
  
  return(list(
    success = TRUE,
    user = username,
    role = valid_users[[username]]$role
  ))
}

#' Generate unique session ID
#' @return Character string session ID
generate_session_id <- function() {
  paste0(
    "session_",
    format(Sys.time(), "%Y%m%d%H%M%S"),
    "_",
    sample(letters, 6, replace = TRUE) |> paste0(collapse = "")
  )
}

#' Check if role has permission
#' @param role User role
#' @param permission Required permission
#' @return Logical
check_permission <- function(role, permission) {
  permissions <- list(
    admin = c("view", "edit", "delete", "admin", "export", "import"),
    analyst = c("view", "edit", "export", "import"),
    user = c("view", "export")
  )
  
  if (is.null(role) || !role %in% names(permissions)) {
    return(FALSE)
  }
  
  permission %in% permissions[[role]]
}

#' Log audit event
#' @param event_type Type of event
#' @param user Username
#' @param details Additional details
log_audit_event <- function(event_type, user, details = list()) {
  # This would normally write to database
  # For now, just log to console
  message(sprintf(
    "[AUDIT] %s | User: %s | Event: %s | Details: %s",
    Sys.time(),
    user,
    event_type,
    jsonlite::toJSON(details, auto_unbox = TRUE)
  ))
}
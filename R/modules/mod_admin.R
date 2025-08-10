# R/modules/mod_admin.R
# Administration Module

#' Admin Module UI
#' @param id Module ID
#' @return Shiny UI elements
#' @export
mod_admin_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      column(12,
        h3("Administration Panel", icon("cogs")),
        hr()
      )
    ),
    
    fluidRow(
      column(12,
        tabsetPanel(
          id = ns("admin_tabs"),
          
          tabPanel(
            "User Management",
            icon = icon("users"),
            br(),
            
            fluidRow(
              column(4,
                box(
                  title = "Add/Edit User",
                  status = "primary",
                  solidHeader = TRUE,
                  width = 12,
                  
                  textInput(
                    ns("new_username"),
                    "Username",
                    placeholder = "Enter username"
                  ),
                  
                  passwordInput(
                    ns("new_password"),
                    "Password",
                    placeholder = "Enter password"
                  ),
                  
                  selectInput(
                    ns("new_role"),
                    "Role",
                    choices = c(
                      "Administrator" = "admin",
                      "Analyst" = "analyst",
                      "User" = "user",
                      "Viewer" = "viewer"
                    )
                  ),
                  
                  textInput(
                    ns("new_email"),
                    "Email",
                    placeholder = "user@example.com"
                  ),
                  
                  checkboxInput(
                    ns("user_active"),
                    "Active",
                    value = TRUE
                  ),
                  
                  hr(),
                  
                  actionButton(
                    ns("add_user"),
                    "Add User",
                    class = "btn-success",
                    icon = icon("user-plus")
                  ),
                  
                  actionButton(
                    ns("update_user"),
                    "Update User",
                    class = "btn-warning",
                    icon = icon("user-edit")
                  ),
                  
                  actionButton(
                    ns("delete_user"),
                    "Delete User",
                    class = "btn-danger",
                    icon = icon("user-times")
                  )
                )
              ),
              
              column(8,
                box(
                  title = "Current Users",
                  status = "info",
                  solidHeader = TRUE,
                  width = 12,
                  
                  DT::DTOutput(ns("users_table"))
                )
              )
            )
          ),
          
          tabPanel(
            "Audit Log",
            icon = icon("history"),
            br(),
            
            fluidRow(
              column(12,
                box(
                  title = "Audit Log Filters",
                  status = "warning",
                  solidHeader = TRUE,
                  width = 12,
                  collapsible = TRUE,
                  
                  fluidRow(
                    column(3,
                      dateRangeInput(
                        ns("audit_date_range"),
                        "Date Range",
                        start = Sys.Date() - 7,
                        end = Sys.Date()
                      )
                    ),
                    column(3,
                      selectInput(
                        ns("audit_user_filter"),
                        "User",
                        choices = c("All" = "", "admin", "user", "analyst"),
                        selected = ""
                      )
                    ),
                    column(3,
                      selectInput(
                        ns("audit_event_filter"),
                        "Event Type",
                        choices = c(
                          "All" = "",
                          "Login" = "LOGIN",
                          "Logout" = "LOGOUT",
                          "Model Fit" = "MODEL_FIT",
                          "Data Upload" = "DATA_UPLOAD",
                          "Export" = "EXPORT"
                        ),
                        selected = ""
                      )
                    ),
                    column(3,
                      br(),
                      actionButton(
                        ns("refresh_audit"),
                        "Refresh",
                        icon = icon("sync"),
                        class = "btn-primary"
                      )
                    )
                  )
                )
              )
            ),
            
            fluidRow(
              column(12,
                box(
                  title = "Audit Events",
                  status = "info",
                  solidHeader = TRUE,
                  width = 12,
                  
                  DT::DTOutput(ns("audit_table"))
                )
              )
            )
          ),
          
          tabPanel(
            "System Settings",
            icon = icon("sliders-h"),
            br(),
            
            fluidRow(
              column(6,
                box(
                  title = "General Settings",
                  status = "primary",
                  solidHeader = TRUE,
                  width = 12,
                  
                  h4("Application Settings"),
                  
                  textInput(
                    ns("app_title"),
                    "Application Title",
                    value = "PK/PD Analysis Platform"
                  ),
                  
                  numericInput(
                    ns("session_timeout"),
                    "Session Timeout (minutes)",
                    value = 30,
                    min = 5,
                    max = 120,
                    step = 5
                  ),
                  
                  numericInput(
                    ns("max_upload_size"),
                    "Max Upload Size (MB)",
                    value = 50,
                    min = 1,
                    max = 500,
                    step = 10
                  ),
                  
                  selectInput(
                    ns("theme"),
                    "UI Theme",
                    choices = c("Default", "Dark", "Light", "Blue"),
                    selected = "Default"
                  ),
                  
                  hr(),
                  
                  h4("Security Settings"),
                  
                  checkboxInput(
                    ns("require_2fa"),
                    "Require Two-Factor Authentication",
                    value = FALSE
                  ),
                  
                  numericInput(
                    ns("password_min_length"),
                    "Minimum Password Length",
                    value = 8,
                    min = 6,
                    max = 20,
                    step = 1
                  ),
                  
                  checkboxInput(
                    ns("password_require_special"),
                    "Require Special Characters in Password",
                    value = TRUE
                  ),
                  
                  numericInput(
                    ns("max_login_attempts"),
                    "Max Login Attempts",
                    value = 5,
                    min = 3,
                    max = 10,
                    step = 1
                  )
                )
              ),
              
              column(6,
                box(
                  title = "Database Settings",
                  status = "warning",
                  solidHeader = TRUE,
                  width = 12,
                  
                  h4("Database Connection"),
                  
                  textInput(
                    ns("db_host"),
                    "Host",
                    value = "localhost"
                  ),
                  
                  numericInput(
                    ns("db_port"),
                    "Port",
                    value = 5432,
                    min = 1,
                    max = 65535
                  ),
                  
                  textInput(
                    ns("db_name"),
                    "Database Name",
                    value = "pkpd_db"
                  ),
                  
                  textInput(
                    ns("db_user"),
                    "Username",
                    value = "pkpd_user"
                  ),
                  
                  passwordInput(
                    ns("db_password"),
                    "Password",
                    placeholder = "Enter database password"
                  ),
                  
                  hr(),
                  
                  actionButton(
                    ns("test_connection"),
                    "Test Connection",
                    icon = icon("plug"),
                    class = "btn-info"
                  ),
                  
                  br(), br(),
                  
                  verbatimTextOutput(ns("connection_status"))
                )
              )
            ),
            
            fluidRow(
              column(12,
                box(
                  title = "Save Settings",
                  status = "success",
                  solidHeader = TRUE,
                  width = 12,
                  
                  actionButton(
                    ns("save_settings"),
                    "Save All Settings",
                    icon = icon("save"),
                    class = "btn-success btn-lg"
                  ),
                  
                  actionButton(
                    ns("reset_settings"),
                    "Reset to Defaults",
                    icon = icon("undo"),
                    class = "btn-warning btn-lg"
                  )
                )
              )
            )
          ),
          
          tabPanel(
            "System Status",
            icon = icon("heartbeat"),
            br(),
            
            fluidRow(
              valueBoxOutput(ns("status_users")),
              valueBoxOutput(ns("status_sessions")),
              valueBoxOutput(ns("status_jobs"))
            ),
            
            br(),
            
            fluidRow(
              column(6,
                box(
                  title = "System Resources",
                  status = "info",
                  solidHeader = TRUE,
                  width = 12,
                  
                  plotOutput(ns("resource_plot"), height = "300px")
                )
              ),
              
              column(6,
                box(
                  title = "Recent Activity",
                  status = "primary",
                  solidHeader = TRUE,
                  width = 12,
                  
                  tableOutput(ns("recent_activity"))
                )
              )
            ),
            
            br(),
            
            fluidRow(
              column(12,
                box(
                  title = "System Information",
                  status = "warning",
                  solidHeader = TRUE,
                  width = 12,
                  
                  verbatimTextOutput(ns("system_info"))
                )
              )
            )
          ),
          
          tabPanel(
            "Backup & Restore",
            icon = icon("database"),
            br(),
            
            fluidRow(
              column(6,
                box(
                  title = "Create Backup",
                  status = "success",
                  solidHeader = TRUE,
                  width = 12,
                  
                  h4("Backup Options"),
                  
                  checkboxGroupInput(
                    ns("backup_options"),
                    "Include in Backup:",
                    choices = c(
                      "User Data" = "users",
                      "Models" = "models",
                      "Results" = "results",
                      "Settings" = "settings",
                      "Audit Logs" = "audit"
                    ),
                    selected = c("users", "models", "results", "settings")
                  ),
                  
                  textInput(
                    ns("backup_name"),
                    "Backup Name",
                    value = paste0("backup_", format(Sys.Date(), "%Y%m%d"))
                  ),
                  
                  hr(),
                  
                  actionButton(
                    ns("create_backup"),
                    "Create Backup",
                    icon = icon("download"),
                    class = "btn-success btn-lg"
                  ),
                  
                  br(), br(),
                  
                  h4("Recent Backups"),
                  
                  DT::DTOutput(ns("backups_table"))
                )
              ),
              
              column(6,
                box(
                  title = "Restore from Backup",
                  status = "danger",
                  solidHeader = TRUE,
                  width = 12,
                  
                  h4("Upload Backup File"),
                  
                  fileInput(
                    ns("restore_file"),
                    "Select Backup File",
                    accept = c(".sql", ".zip", ".tar.gz")
                  ),
                  
                  hr(),
                  
                  h4("Restore Options"),
                  
                  checkboxGroupInput(
                    ns("restore_options"),
                    "Restore:",
                    choices = c(
                      "User Data" = "users",
                      "Models" = "models",
                      "Results" = "results",
                      "Settings" = "settings",
                      "Audit Logs" = "audit"
                    ),
                    selected = c("users", "models", "results", "settings")
                  ),
                  
                  checkboxInput(
                    ns("restore_confirm"),
                    "I understand this will overwrite existing data",
                    value = FALSE
                  ),
                  
                  hr(),
                  
                  actionButton(
                    ns("restore_backup"),
                    "Restore Backup",
                    icon = icon("upload"),
                    class = "btn-danger btn-lg"
                  )
                )
              )
            )
          )
        )
      )
    )
  )
}

#' Admin Module Server
#' @param id Module ID
#' @param auth Authentication state
#' @return Reactive values with admin state
#' @export
mod_admin_server <- function(id, auth) {
  moduleServer(id, function(input, output, session) {
    
    ns <- session$ns
    
    # Check admin permissions
    observe({
      if (!auth$has_permission("admin")) {
        showNotification(
          "Access denied. Admin privileges required.",
          type = "error",
          duration = NULL
        )
      }
    })
    
    # Mock data for demonstration
    users_data <- reactiveVal(
      data.frame(
        Username = c("admin", "analyst1", "user1", "viewer1"),
        Role = c("admin", "analyst", "user", "viewer"),
        Email = c("admin@example.com", "analyst@example.com", 
                 "user@example.com", "viewer@example.com"),
        Active = c(TRUE, TRUE, TRUE, FALSE),
        Last_Login = Sys.time() - runif(4, 0, 7*24*60*60),
        stringsAsFactors = FALSE
      )
    )
    
    audit_data <- reactiveVal(
      data.frame(
        Timestamp = Sys.time() - runif(20, 0, 7*24*60*60),
        User = sample(c("admin", "user", "analyst"), 20, replace = TRUE),
        Event = sample(c("LOGIN", "LOGOUT", "MODEL_FIT", "DATA_UPLOAD"), 
                      20, replace = TRUE),
        Details = paste("Action performed", 1:20),
        IP_Address = paste0("192.168.1.", sample(1:255, 20)),
        stringsAsFactors = FALSE
      )
    )
    
    # User Management
    output$users_table <- DT::renderDT({
      DT::datatable(
        users_data(),
        options = list(
          pageLength = 10,
          scrollX = TRUE
        ),
        selection = "single",
        rownames = FALSE
      )
    })
    
    observeEvent(input$add_user, {
      req(input$new_username, input$new_password)
      req(auth$has_permission("admin"))
      
      # Add new user logic
      current_users <- users_data()
      new_user <- data.frame(
        Username = input$new_username,
        Role = input$new_role,
        Email = input$new_email,
        Active = input$user_active,
        Last_Login = NA,
        stringsAsFactors = FALSE
      )
      
      users_data(rbind(current_users, new_user))
      
      showNotification(
        paste("User", input$new_username, "added successfully"),
        type = "success"
      )
      
      # Clear inputs
      updateTextInput(session, "new_username", value = "")
      updatePasswordInput(session, "new_password", value = "")
      updateTextInput(session, "new_email", value = "")
    })
    
    # Audit Log
    output$audit_table <- DT::renderDT({
      data_to_show <- audit_data()
      
      # Apply filters
      if (input$audit_user_filter != "") {
        data_to_show <- data_to_show[data_to_show$User == input$audit_user_filter, ]
      }
      
      if (input$audit_event_filter != "") {
        data_to_show <- data_to_show[data_to_show$Event == input$audit_event_filter, ]
      }
      
      # Apply date range
      data_to_show <- data_to_show[
        data_to_show$Timestamp >= input$audit_date_range[1] &
        data_to_show$Timestamp <= input$audit_date_range[2], ]
      
      DT::datatable(
        data_to_show,
        options = list(
          pageLength = 15,
          scrollX = TRUE,
          order = list(list(0, 'desc'))
        ),
        rownames = FALSE
      ) %>%
        DT::formatDate("Timestamp", method = "toLocaleString")
    })
    
    # System Status
    output$status_users <- renderValueBox({
      valueBox(
        value = nrow(users_data()),
        subtitle = "Total Users",
        icon = icon("users"),
        color = "blue"
      )
    })
    
    output$status_sessions <- renderValueBox({
      valueBox(
        value = sample(1:10, 1),
        subtitle = "Active Sessions",
        icon = icon("plug"),
        color = "green"
      )
    })
    
    output$status_jobs <- renderValueBox({
      valueBox(
        value = sample(0:5, 1),
        subtitle = "Running Jobs",
        icon = icon("spinner"),
        color = "yellow"
      )
    })
    
    # Resource plot
    output$resource_plot <- renderPlot({
      # Mock resource usage
      resources <- data.frame(
        Resource = c("CPU", "Memory", "Disk", "Network"),
        Usage = c(45, 62, 38, 25)
      )
      
      ggplot(resources, aes(x = Resource, y = Usage, fill = Resource)) +
        geom_bar(stat = "identity") +
        geom_hline(yintercept = 80, color = "red", linetype = "dashed") +
        ylim(0, 100) +
        labs(y = "Usage (%)", title = "System Resource Usage") +
        theme_minimal() +
        theme(legend.position = "none")
    })
    
    # Recent activity
    output$recent_activity <- renderTable({
      data.frame(
        Time = format(Sys.time() - runif(5, 0, 60*60), "%H:%M"),
        User = sample(c("admin", "user", "analyst"), 5, replace = TRUE),
        Action = sample(c("Login", "Run Model", "Export Data"), 5, replace = TRUE)
      )
    })
    
    # System info
    output$system_info <- renderPrint({
      cat("System Information\n")
      cat("==================\n\n")
      cat("R Version:", R.version.string, "\n")
      cat("Platform:", R.version$platform, "\n")
      cat("OS:", Sys.info()["sysname"], Sys.info()["release"], "\n")
      cat("Hostname:", Sys.info()["nodename"], "\n")
      cat("User:", Sys.info()["user"], "\n")
      cat("\nShiny Version:", packageVersion("shiny"), "\n")
      cat("Working Directory:", getwd(), "\n")
      cat("Temp Directory:", tempdir(), "\n")
      cat("\nMemory Usage:\n")
      print(gc())
    })
    
    # Database connection test
    observeEvent(input$test_connection, {
      output$connection_status <- renderPrint({
        cat("Testing connection to:\n")
        cat("Host:", input$db_host, "\n")
        cat("Port:", input$db_port, "\n")
        cat("Database:", input$db_name, "\n")
        cat("\nStatus: Connection successful!\n")
        cat("PostgreSQL version: 13.4\n")
        cat("Connection pool size: 5\n")
      })
    })
    
    # Save settings
    observeEvent(input$save_settings, {
      showNotification(
        "Settings saved successfully",
        type = "success",
        duration = 5
      )
      
      # Log the event
      log_audit_event(
        event_type = "SETTINGS_CHANGED",
        user = auth$get_user(),
        details = list(
          settings = c("general", "security", "database")
        )
      )
    })
    
    # Backups table
    output$backups_table <- DT::renderDT({
      backups <- data.frame(
        Name = c("backup_20250110", "backup_20250109", "backup_20250108"),
        Date = Sys.Date() - 0:2,
        Size = c("245 MB", "238 MB", "241 MB"),
        Status = c("Complete", "Complete", "Complete")
      )
      
      DT::datatable(
        backups,
        options = list(
          pageLength = 5,
          dom = 't'
        ),
        rownames = FALSE
      )
    })
    
    # Create backup
    observeEvent(input$create_backup, {
      showNotification(
        "Creating backup...",
        type = "message",
        id = "backup_notification",
        duration = NULL
      )
      
      # Simulate backup creation
      Sys.sleep(2)
      
      removeNotification("backup_notification")
      showNotification(
        paste("Backup", input$backup_name, "created successfully"),
        type = "success",
        duration = 5
      )
    })
    
    # Restore backup
    observeEvent(input$restore_backup, {
      req(input$restore_confirm)
      req(input$restore_file)
      
      showModal(modalDialog(
        title = "Confirm Restore",
        "Are you sure you want to restore from this backup? This action cannot be undone.",
        footer = tagList(
          modalButton("Cancel"),
          actionButton(ns("confirm_restore"), "Restore", class = "btn-danger")
        )
      ))
    })
    
    observeEvent(input$confirm_restore, {
      removeModal()
      showNotification(
        "Restoring from backup...",
        type = "warning",
        duration = 10
      )
    })
    
    # Return admin state
    return(reactive({
      list(
        users = users_data(),
        settings = list(
          session_timeout = input$session_timeout,
          max_upload_size = input$max_upload_size,
          theme = input$theme
        )
      )
    }))
  })
}
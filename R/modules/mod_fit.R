# R/modules/mod_fit.R
# PK/PD Model Fitting Module

#' Fitting Module UI
#' @param id Module ID
#' @return Shiny UI elements
#' @export
mod_fit_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      # Left panel - Configuration
      column(4,
        box(
          title = "Model Configuration",
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          
          selectInput(
            ns("model_type"),
            "Model Type",
            choices = c(
              "One Compartment" = "one_comp",
              "Two Compartment" = "two_comp",
              "Three Compartment" = "three_comp",
              "One Compartment with Absorption" = "one_comp_abs",
              "Two Compartment with Absorption" = "two_comp_abs"
            ),
            selected = "one_comp"
          ),
          
          selectInput(
            ns("error_model"),
            "Error Model",
            choices = c(
              "Additive" = "additive",
              "Proportional" = "proportional",
              "Combined" = "combined"
            ),
            selected = "proportional"
          ),
          
          numericInput(
            ns("n_chains"),
            "Number of MCMC Chains",
            value = 3,
            min = 1,
            max = 10,
            step = 1
          ),
          
          numericInput(
            ns("n_iter"),
            "Iterations per Chain",
            value = 10000,
            min = 1000,
            max = 100000,
            step = 1000
          ),
          
          numericInput(
            ns("n_burnin"),
            "Burn-in Iterations",
            value = 5000,
            min = 0,
            max = 50000,
            step = 1000
          ),
          
          numericInput(
            ns("n_thin"),
            "Thinning Interval",
            value = 1,
            min = 1,
            max = 100,
            step = 1
          ),
          
          hr(),
          
          h4("Initial Values"),
          
          numericInput(
            ns("init_cl"),
            "Clearance (CL) - L/h",
            value = 5,
            min = 0.01,
            max = 100,
            step = 0.1
          ),
          
          numericInput(
            ns("init_v"),
            "Volume (V) - L",
            value = 50,
            min = 0.1,
            max = 1000,
            step = 1
          ),
          
          conditionalPanel(
            condition = "input.model_type.includes('two_comp') || input.model_type.includes('three_comp')",
            ns = ns,
            numericInput(
              ns("init_q"),
              "Inter-compartmental Clearance (Q) - L/h",
              value = 10,
              min = 0.01,
              max = 100,
              step = 0.1
            ),
            numericInput(
              ns("init_v2"),
              "Peripheral Volume (V2) - L",
              value = 100,
              min = 0.1,
              max = 1000,
              step = 1
            )
          ),
          
          conditionalPanel(
            condition = "input.model_type.includes('abs')",
            ns = ns,
            numericInput(
              ns("init_ka"),
              "Absorption Rate (Ka) - 1/h",
              value = 1,
              min = 0.01,
              max = 10,
              step = 0.1
            )
          ),
          
          hr(),
          
          actionButton(
            ns("run_fit"),
            "Run Model Fitting",
            class = "btn-success",
            icon = icon("play"),
            width = "100%"
          ),
          
          br(), br(),
          
          downloadButton(
            ns("download_results"),
            "Download Results",
            class = "btn-info",
            style = "width: 100%;"
          )
        )
      ),
      
      # Right panel - Results
      column(8,
        tabsetPanel(
          id = ns("results_tabs"),
          
          tabPanel(
            "Data Summary",
            icon = icon("table"),
            br(),
            DT::DTOutput(ns("data_summary")),
            br(),
            plotlyOutput(ns("data_plot"), height = "400px")
          ),
          
          tabPanel(
            "Fitting Progress",
            icon = icon("spinner"),
            br(),
            verbatimTextOutput(ns("fit_progress")),
            br(),
            plotOutput(ns("convergence_plot"), height = "400px")
          ),
          
          tabPanel(
            "Parameter Estimates",
            icon = icon("chart-bar"),
            br(),
            DT::DTOutput(ns("param_table")),
            br(),
            plotOutput(ns("param_dist_plot"), height = "500px")
          ),
          
          tabPanel(
            "Individual Fits",
            icon = icon("user"),
            br(),
            selectInput(
              ns("subject_select"),
              "Select Subject",
              choices = NULL,
              width = "200px"
            ),
            plotlyOutput(ns("individual_fit_plot"), height = "500px")
          ),
          
          tabPanel(
            "Population Predictions",
            icon = icon("users"),
            br(),
            plotlyOutput(ns("population_plot"), height = "500px")
          )
        )
      )
    )
  )
}

#' Fitting Module Server
#' @param id Module ID
#' @param data Reactive data object
#' @param auth Authentication state
#' @return Reactive values with fitting results
#' @export
mod_fit_server <- function(id, data, auth) {
  moduleServer(id, function(input, output, session) {
    
    ns <- session$ns
    
    # Initialize reactive values for results
    fit_results <- reactiveValues(
      model = NULL,
      parameters = NULL,
      predictions = NULL,
      diagnostics = NULL,
      status = "idle",
      error = NULL
    )
    
    # Update subject selector when data changes
    observe({
      req(data())
      subjects <- unique(data()$ID)
      updateSelectInput(
        session,
        "subject_select",
        choices = subjects,
        selected = subjects[1]
      )
    })
    
    # Data summary table
    output$data_summary <- DT::renderDT({
      req(data())
      
      summary_data <- data() %>%
        group_by(ID) %>%
        summarise(
          N_obs = n(),
          First_time = min(TIME),
          Last_time = max(TIME),
          Min_conc = min(DV, na.rm = TRUE),
          Max_conc = max(DV, na.rm = TRUE),
          .groups = "drop"
        )
      
      DT::datatable(
        summary_data,
        options = list(
          pageLength = 10,
          scrollX = TRUE
        ),
        rownames = FALSE
      ) %>%
        DT::formatRound(c("First_time", "Last_time", "Min_conc", "Max_conc"), 2)
    })
    
    # Data visualization
    output$data_plot <- renderPlotly({
      req(data())
      
      p <- ggplot(data(), aes(x = TIME, y = DV, color = factor(ID))) +
        geom_point(size = 2, alpha = 0.7) +
        geom_line(alpha = 0.5) +
        scale_y_log10() +
        labs(
          x = "Time (hours)",
          y = "Concentration (ng/mL)",
          color = "Subject ID",
          title = "Observed Concentration-Time Profiles"
        ) +
        theme_minimal() +
        theme(legend.position = "right")
      
      ggplotly(p)
    })
    
    # Run fitting when button clicked
    observeEvent(input$run_fit, {
      req(data())
      req(auth$has_permission("edit"))
      
      # Update status
      fit_results$status <- "running"
      fit_results$error <- NULL
      
      # Show notification
      showNotification(
        "Starting model fitting...",
        type = "message",
        id = "fit_notification"
      )
      
      # Prepare model configuration
      model_config <- list(
        model_type = input$model_type,
        error_model = input$error_model,
        n_chains = input$n_chains,
        n_iter = input$n_iter,
        n_burnin = input$n_burnin,
        n_thin = input$n_thin,
        initial_values = list(
          CL = input$init_cl,
          V = input$init_v,
          Q = input$init_q,
          V2 = input$init_v2,
          Ka = input$init_ka
        )
      )
      
      # Run fitting (using run_fit_jags)
      tryCatch({
        results <- run_fit_jags(
          data = data(),
          config = model_config,
          progress_callback = function(msg) {
            # Update progress
            output$fit_progress <- renderText({
              paste(
                "Status:", msg,
                "\nModel:", input$model_type,
                "\nChains:", input$n_chains,
                "\nIterations:", input$n_iter
              )
            })
          }
        )
        
        # Store results
        fit_results$model <- results$model
        fit_results$parameters <- results$parameters
        fit_results$predictions <- results$predictions
        fit_results$diagnostics <- results$diagnostics
        fit_results$status <- "completed"
        
        # Update notification
        removeNotification("fit_notification")
        showNotification(
          "Model fitting completed successfully!",
          type = "success",
          duration = 5
        )
        
        # Log event
        log_audit_event(
          event_type = "MODEL_FIT",
          user = auth$get_user(),
          details = list(
            model_type = input$model_type,
            n_subjects = length(unique(data()$ID)),
            n_observations = nrow(data())
          )
        )
        
      }, error = function(e) {
        fit_results$status <- "error"
        fit_results$error <- e$message
        
        removeNotification("fit_notification")
        showNotification(
          paste("Fitting error:", e$message),
          type = "error",
          duration = NULL
        )
      })
    })
    
    # Parameter estimates table
    output$param_table <- DT::renderDT({
      req(fit_results$parameters)
      
      param_summary <- fit_results$parameters %>%
        mutate(
          CV_percent = (SD / Mean) * 100,
          RSE_percent = (SE / Mean) * 100
        )
      
      DT::datatable(
        param_summary,
        options = list(
          pageLength = 20,
          scrollX = TRUE
        ),
        rownames = FALSE
      ) %>%
        DT::formatRound(c("Mean", "Median", "SD", "SE", "CI_2.5", "CI_97.5"), 3) %>%
        DT::formatRound(c("CV_percent", "RSE_percent"), 1)
    })
    
    # Parameter distribution plot
    output$param_dist_plot <- renderPlot({
      req(fit_results$model)
      
      # Extract MCMC samples
      samples <- as.matrix(fit_results$model)
      
      # Create density plots for main parameters
      par(mfrow = c(2, 2))
      for (param in c("CL", "V", "Q", "V2")[1:min(4, ncol(samples))]) {
        if (param %in% colnames(samples)) {
          plot(density(samples[, param]),
               main = paste("Posterior Distribution:", param),
               xlab = param,
               col = "blue",
               lwd = 2)
          abline(v = median(samples[, param]), col = "red", lty = 2)
        }
      }
    })
    
    # Convergence diagnostics plot
    output$convergence_plot <- renderPlot({
      req(fit_results$model)
      
      # Create trace plots
      plot(fit_results$model, trace = TRUE, density = FALSE)
    })
    
    # Individual fit plot
    output$individual_fit_plot <- renderPlotly({
      req(fit_results$predictions)
      req(input$subject_select)
      
      subject_data <- data() %>%
        filter(ID == input$subject_select)
      
      subject_pred <- fit_results$predictions %>%
        filter(ID == input$subject_select)
      
      p <- ggplot() +
        geom_point(
          data = subject_data,
          aes(x = TIME, y = DV),
          color = "blue",
          size = 3,
          alpha = 0.7
        ) +
        geom_line(
          data = subject_pred,
          aes(x = TIME, y = IPRED),
          color = "red",
          size = 1
        ) +
        geom_ribbon(
          data = subject_pred,
          aes(x = TIME, ymin = IPRED_CI_2.5, ymax = IPRED_CI_97.5),
          alpha = 0.2,
          fill = "red"
        ) +
        scale_y_log10() +
        labs(
          x = "Time (hours)",
          y = "Concentration (ng/mL)",
          title = paste("Individual Fit - Subject", input$subject_select)
        ) +
        theme_minimal()
      
      ggplotly(p)
    })
    
    # Population predictions plot
    output$population_plot <- renderPlotly({
      req(fit_results$predictions)
      
      pop_summary <- fit_results$predictions %>%
        group_by(TIME) %>%
        summarise(
          PRED_median = median(PRED),
          PRED_q25 = quantile(PRED, 0.25),
          PRED_q75 = quantile(PRED, 0.75),
          PRED_q05 = quantile(PRED, 0.05),
          PRED_q95 = quantile(PRED, 0.95),
          .groups = "drop"
        )
      
      p <- ggplot() +
        geom_point(
          data = data(),
          aes(x = TIME, y = DV),
          alpha = 0.3,
          color = "gray40"
        ) +
        geom_line(
          data = pop_summary,
          aes(x = TIME, y = PRED_median),
          color = "blue",
          size = 1.5
        ) +
        geom_ribbon(
          data = pop_summary,
          aes(x = TIME, ymin = PRED_q25, ymax = PRED_q75),
          alpha = 0.3,
          fill = "blue"
        ) +
        geom_ribbon(
          data = pop_summary,
          aes(x = TIME, ymin = PRED_q05, ymax = PRED_q95),
          alpha = 0.2,
          fill = "blue"
        ) +
        scale_y_log10() +
        labs(
          x = "Time (hours)",
          y = "Concentration (ng/mL)",
          title = "Population Predictions with Uncertainty"
        ) +
        theme_minimal()
      
      ggplotly(p)
    })
    
    # Download results
    output$download_results <- downloadHandler(
      filename = function() {
        paste0("fit_results_", Sys.Date(), ".RData")
      },
      content = function(file) {
        results_to_save <- list(
          model = fit_results$model,
          parameters = fit_results$parameters,
          predictions = fit_results$predictions,
          diagnostics = fit_results$diagnostics,
          config = list(
            model_type = input$model_type,
            error_model = input$error_model,
            n_chains = input$n_chains,
            n_iter = input$n_iter
          ),
          timestamp = Sys.time()
        )
        save(results_to_save, file = file)
      }
    )
    
    # Return fitting results for use by other modules
    return(reactive({
      list(
        results = fit_results,
        config = list(
          model_type = input$model_type,
          error_model = input$error_model
        )
      )
    }))
  })
}

# Placeholder for run_fit_jags function
# This would normally be in R/run_fit_jags.R
run_fit_jags <- function(data, config, progress_callback = NULL) {
  # Simulate fitting process
  if (!is.null(progress_callback)) {
    progress_callback("Initializing JAGS model...")
  }
  
  Sys.sleep(1)  # Simulate processing
  
  if (!is.null(progress_callback)) {
    progress_callback("Running MCMC chains...")
  }
  
  # Return mock results
  list(
    model = list(),  # Would be actual JAGS model
    parameters = data.frame(
      Parameter = c("CL", "V", "Q", "V2"),
      Mean = c(5.2, 48.3, 9.8, 95.2),
      Median = c(5.1, 48.0, 9.7, 94.8),
      SD = c(0.8, 5.2, 1.2, 12.3),
      SE = c(0.08, 0.52, 0.12, 1.23),
      CI_2.5 = c(3.8, 38.5, 7.5, 72.1),
      CI_97.5 = c(6.9, 58.9, 12.3, 120.5)
    ),
    predictions = data.frame(
      ID = rep(unique(data$ID), each = 24),
      TIME = rep(seq(0, 23), length(unique(data$ID))),
      PRED = runif(24 * length(unique(data$ID)), 1, 100),
      IPRED = runif(24 * length(unique(data$ID)), 1, 100),
      IPRED_CI_2.5 = runif(24 * length(unique(data$ID)), 0.5, 80),
      IPRED_CI_97.5 = runif(24 * length(unique(data$ID)), 20, 120)
    ),
    diagnostics = list(
      DIC = 1234.5,
      pD = 45.6,
      Rhat = c(CL = 1.01, V = 1.02, Q = 1.01, V2 = 1.01)
    )
  )
}
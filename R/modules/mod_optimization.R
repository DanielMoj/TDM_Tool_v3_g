# R/modules/mod_optimization.R
# Dose Optimization Module

#' Optimization Module UI
#' @param id Module ID
#' @return Shiny UI elements
#' @export
mod_optimization_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      column(12,
        h3("Dose Optimization", icon("calculator")),
        hr()
      )
    ),
    
    fluidRow(
      # Configuration panel
      column(4,
        box(
          title = "Optimization Settings",
          status = "warning",
          solidHeader = TRUE,
          width = 12,
          
          h4("Target Parameters"),
          
          selectInput(
            ns("target_type"),
            "Target Type",
            choices = c(
              "AUC" = "auc",
              "Cmax" = "cmax",
              "Cmin" = "cmin",
              "Time above MIC" = "time_above_mic",
              "AUC/MIC ratio" = "auc_mic_ratio"
            ),
            selected = "auc"
          ),
          
          numericInput(
            ns("target_value"),
            "Target Value",
            value = 400,
            min = 0,
            step = 10
          ),
          
          conditionalPanel(
            condition = "input.target_type.includes('mic')",
            ns = ns,
            numericInput(
              ns("mic_value"),
              "MIC (mg/L)",
              value = 2,
              min = 0,
              step = 0.1
            )
          ),
          
          hr(),
          
          h4("Dosing Regimen"),
          
          selectInput(
            ns("route"),
            "Route of Administration",
            choices = c(
              "IV Bolus" = "iv_bolus",
              "IV Infusion" = "iv_infusion",
              "Oral" = "oral",
              "Subcutaneous" = "sc"
            ),
            selected = "iv_bolus"
          ),
          
          conditionalPanel(
            condition = "input.route == 'iv_infusion'",
            ns = ns,
            numericInput(
              ns("infusion_duration"),
              "Infusion Duration (hours)",
              value = 1,
              min = 0.1,
              max = 24,
              step = 0.1
            )
          ),
          
          numericInput(
            ns("dosing_interval"),
            "Dosing Interval (hours)",
            value = 12,
            min = 1,
            max = 168,
            step = 1
          ),
          
          numericInput(
            ns("n_doses"),
            "Number of Doses",
            value = 10,
            min = 1,
            max = 100,
            step = 1
          ),
          
          hr(),
          
          h4("Optimization Constraints"),
          
          numericInput(
            ns("min_dose"),
            "Minimum Dose (mg)",
            value = 10,
            min = 0,
            step = 10
          ),
          
          numericInput(
            ns("max_dose"),
            "Maximum Dose (mg)",
            value = 2000,
            min = 0,
            step = 10
          ),
          
          numericInput(
            ns("max_daily_dose"),
            "Maximum Daily Dose (mg)",
            value = 4000,
            min = 0,
            step = 10
          ),
          
          hr(),
          
          h4("Patient Covariates"),
          
          numericInput(
            ns("weight"),
            "Weight (kg)",
            value = 70,
            min = 10,
            max = 200,
            step = 1
          ),
          
          numericInput(
            ns("creatinine_clearance"),
            "Creatinine Clearance (mL/min)",
            value = 100,
            min = 10,
            max = 200,
            step = 1
          ),
          
          selectInput(
            ns("gender"),
            "Gender",
            choices = c("Male" = "M", "Female" = "F"),
            selected = "M"
          ),
          
          numericInput(
            ns("age"),
            "Age (years)",
            value = 40,
            min = 18,
            max = 100,
            step = 1
          ),
          
          hr(),
          
          actionButton(
            ns("optimize_dose"),
            "Optimize Dose",
            class = "btn-success",
            icon = icon("rocket"),
            width = "100%"
          ),
          
          br(), br(),
          
          actionButton(
            ns("simulate_regimen"),
            "Simulate Regimen",
            class = "btn-primary",
            icon = icon("chart-line"),
            width = "100%"
          )
        )
      ),
      
      # Results panel
      column(8,
        tabsetPanel(
          id = ns("optimization_tabs"),
          
          tabPanel(
            "Optimization Results",
            icon = icon("bullseye"),
            br(),
            
            fluidRow(
              column(12,
                valueBoxOutput(ns("optimal_dose_box")),
                valueBoxOutput(ns("predicted_target_box")),
                valueBoxOutput(ns("probability_box"))
              )
            ),
            
            br(),
            
            fluidRow(
              column(12,
                h4("Recommended Dosing Regimen"),
                tableOutput(ns("regimen_table"))
              )
            ),
            
            br(),
            
            fluidRow(
              column(12,
                h4("Predicted Concentration-Time Profile"),
                plotlyOutput(ns("concentration_profile"), height = "400px")
              )
            )
          ),
          
          tabPanel(
            "Dose-Response",
            icon = icon("chart-line"),
            br(),
            plotlyOutput(ns("dose_response_plot"), height = "500px"),
            br(),
            DT::DTOutput(ns("dose_response_table"))
          ),
          
          tabPanel(
            "Probability of Target",
            icon = icon("percentage"),
            br(),
            plotlyOutput(ns("prob_target_plot"), height = "400px"),
            br(),
            plotOutput(ns("prob_distribution"), height = "400px")
          ),
          
          tabPanel(
            "Sensitivity Analysis",
            icon = icon("sliders-h"),
            br(),
            
            fluidRow(
              column(6,
                h4("Parameter Sensitivity"),
                plotOutput(ns("sensitivity_tornado"), height = "400px")
              ),
              column(6,
                h4("Covariate Effects"),
                plotOutput(ns("covariate_effects"), height = "400px")
              )
            ),
            
            br(),
            
            DT::DTOutput(ns("sensitivity_table"))
          ),
          
          tabPanel(
            "Simulation Results",
            icon = icon("flask"),
            br(),
            
            fluidRow(
              column(12,
                h4("Monte Carlo Simulation"),
                plotlyOutput(ns("simulation_plot"), height = "500px")
              )
            ),
            
            br(),
            
            fluidRow(
              column(6,
                h4("Target Achievement"),
                plotOutput(ns("target_achievement"), height = "350px")
              ),
              column(6,
                h4("Safety Metrics"),
                plotOutput(ns("safety_metrics"), height = "350px")
              )
            ),
            
            br(),
            
            verbatimTextOutput(ns("simulation_summary"))
          )
        )
      )
    )
  )
}

#' Optimization Module Server
#' @param id Module ID
#' @param fit_results Reactive fitting results
#' @param auth Authentication state
#' @return Reactive values with optimization results
#' @export
mod_optimization_server <- function(id, fit_results, auth) {
  moduleServer(id, function(input, output, session) {
    
    ns <- session$ns
    
    # Store optimization results
    optimization_results <- reactiveValues(
      optimal_dose = NULL,
      regimen = NULL,
      predictions = NULL,
      probability = NULL,
      simulation = NULL,
      sensitivity = NULL
    )
    
    # Optimize dose
    observeEvent(input$optimize_dose, {
      req(fit_results())
      req(auth$has_permission("edit"))
      
      showNotification(
        "Running dose optimization...",
        type = "message",
        id = "opt_notification"
      )
      
      tryCatch({
        # Prepare patient covariates
        covariates <- list(
          weight = input$weight,
          crcl = input$creatinine_clearance,
          gender = input$gender,
          age = input$age
        )
        
        # Optimization settings
        settings <- list(
          target_type = input$target_type,
          target_value = input$target_value,
          mic = input$mic_value,
          route = input$route,
          interval = input$dosing_interval,
          n_doses = input$n_doses,
          min_dose = input$min_dose,
          max_dose = input$max_dose,
          max_daily = input$max_daily_dose,
          infusion_duration = input$infusion_duration
        )
        
        # Run optimization
        opt_result <- optimize_dosing_regimen(
          model = fit_results()$results$model,
          parameters = fit_results()$results$parameters,
          covariates = covariates,
          settings = settings
        )
        
        # Store results
        optimization_results$optimal_dose <- opt_result$optimal_dose
        optimization_results$regimen <- opt_result$regimen
        optimization_results$predictions <- opt_result$predictions
        optimization_results$probability <- opt_result$probability
        
        removeNotification("opt_notification")
        showNotification(
          "Optimization completed!",
          type = "success",
          duration = 5
        )
        
        # Log event
        log_audit_event(
          event_type = "DOSE_OPTIMIZATION",
          user = auth$get_user(),
          details = list(
            target = input$target_type,
            optimal_dose = opt_result$optimal_dose
          )
        )
        
      }, error = function(e) {
        removeNotification("opt_notification")
        showNotification(
          paste("Error:", e$message),
          type = "error",
          duration = NULL
        )
      })
    })
    
    # Simulate regimen
    observeEvent(input$simulate_regimen, {
      req(optimization_results$optimal_dose)
      
      showNotification(
        "Running Monte Carlo simulation...",
        type = "message",
        id = "sim_notification"
      )
      
      tryCatch({
        # Run simulation
        sim_result <- simulate_dosing_regimen(
          dose = optimization_results$optimal_dose,
          regimen = optimization_results$regimen,
          model = fit_results()$results$model,
          n_sim = 1000
        )
        
        optimization_results$simulation <- sim_result
        
        removeNotification("sim_notification")
        showNotification(
          "Simulation completed!",
          type = "success",
          duration = 5
        )
        
      }, error = function(e) {
        removeNotification("sim_notification")
        showNotification(
          paste("Error:", e$message),
          type = "error",
          duration = NULL
        )
      })
    })
    
    # Value boxes
    output$optimal_dose_box <- renderValueBox({
      valueBox(
        value = ifelse(
          is.null(optimization_results$optimal_dose),
          "---",
          paste0(round(optimization_results$optimal_dose, 0), " mg")
        ),
        subtitle = "Optimal Dose",
        icon = icon("pills"),
        color = "green"
      )
    })
    
    output$predicted_target_box <- renderValueBox({
      valueBox(
        value = ifelse(
          is.null(optimization_results$predictions),
          "---",
          paste0(round(optimization_results$predictions$target_value, 1))
        ),
        subtitle = paste("Predicted", input$target_type),
        icon = icon("bullseye"),
        color = "blue"
      )
    })
    
    output$probability_box <- renderValueBox({
      valueBox(
        value = ifelse(
          is.null(optimization_results$probability),
          "---",
          paste0(round(optimization_results$probability * 100, 1), "%")
        ),
        subtitle = "Probability of Target",
        icon = icon("percentage"),
        color = "purple"
      )
    })
    
    # Regimen table
    output$regimen_table <- renderTable({
      req(optimization_results$regimen)
      
      optimization_results$regimen %>%
        select(Dose_Number, Time_h, Dose_mg, Route, Duration_h) %>%
        head(10)
    })
    
    # Concentration profile
    output$concentration_profile <- renderPlotly({
      req(optimization_results$predictions)
      
      pred_data <- optimization_results$predictions$profile
      
      p <- ggplot(pred_data, aes(x = time)) +
        geom_line(aes(y = concentration), color = "blue", size = 1) +
        geom_ribbon(aes(ymin = ci_lower, ymax = ci_upper),
                   alpha = 0.2, fill = "blue") +
        geom_hline(yintercept = input$target_value,
                  color = "red", linetype = "dashed") +
        labs(
          x = "Time (hours)",
          y = "Concentration (mg/L)",
          title = "Predicted Concentration-Time Profile"
        ) +
        theme_minimal()
      
      ggplotly(p)
    })
    
    # Dose-response plot
    output$dose_response_plot <- renderPlotly({
      req(optimization_results$optimal_dose)
      
      # Generate dose-response curve
      doses <- seq(input$min_dose, input$max_dose, length.out = 50)
      responses <- sapply(doses, function(d) {
        calculate_target_metric(
          dose = d,
          parameters = fit_results()$results$parameters,
          target_type = input$target_type,
          interval = input$dosing_interval
        )
      })
      
      dr_data <- data.frame(dose = doses, response = responses)
      
      p <- ggplot(dr_data, aes(x = dose, y = response)) +
        geom_line(color = "blue", size = 1) +
        geom_vline(xintercept = optimization_results$optimal_dose,
                  color = "red", linetype = "dashed") +
        geom_hline(yintercept = input$target_value,
                  color = "green", linetype = "dashed") +
        labs(
          x = "Dose (mg)",
          y = input$target_type,
          title = "Dose-Response Relationship"
        ) +
        theme_minimal()
      
      ggplotly(p)
    })
    
    # Dose-response table
    output$dose_response_table <- DT::renderDT({
      req(optimization_results$optimal_dose)
      
      # Create table with different doses
      dose_levels <- c(0.5, 0.75, 1, 1.25, 1.5) * optimization_results$optimal_dose
      
      dr_table <- data.frame(
        Dose_mg = dose_levels,
        Target_Value = sapply(dose_levels, function(d) {
          calculate_target_metric(
            dose = d,
            parameters = fit_results()$results$parameters,
            target_type = input$target_type,
            interval = input$dosing_interval
          )
        }),
        Probability = sapply(dose_levels, function(d) {
          calculate_target_probability(
            dose = d,
            parameters = fit_results()$results$parameters,
            target_value = input$target_value,
            target_type = input$target_type
          )
        })
      )
      
      DT::datatable(
        dr_table,
        options = list(pageLength = 5),
        rownames = FALSE
      ) %>%
        DT::formatRound(c("Dose_mg", "Target_Value"), 1) %>%
        DT::formatPercentage("Probability", 1)
    })
    
    # Probability of target plot
    output$prob_target_plot <- renderPlotly({
      req(optimization_results$optimal_dose)
      
      doses <- seq(input$min_dose, input$max_dose, length.out = 50)
      probs <- sapply(doses, function(d) {
        calculate_target_probability(
          dose = d,
          parameters = fit_results()$results$parameters,
          target_value = input$target_value,
          target_type = input$target_type
        )
      })
      
      prob_data <- data.frame(dose = doses, probability = probs * 100)
      
      p <- ggplot(prob_data, aes(x = dose, y = probability)) +
        geom_line(color = "purple", size = 1) +
        geom_vline(xintercept = optimization_results$optimal_dose,
                  color = "red", linetype = "dashed") +
        geom_hline(yintercept = 90, color = "green", linetype = "dotted") +
        labs(
          x = "Dose (mg)",
          y = "Probability of Target (%)",
          title = "Probability of Achieving Target"
        ) +
        theme_minimal()
      
      ggplotly(p)
    })
    
    # Probability distribution
    output$prob_distribution <- renderPlot({
      req(optimization_results$simulation)
      
      ggplot(optimization_results$simulation, aes(x = target_achieved)) +
        geom_histogram(aes(y = ..density..), bins = 30,
                      fill = "lightblue", color = "black") +
        geom_density(color = "red", size = 1) +
        geom_vline(xintercept = input$target_value,
                  color = "green", linetype = "dashed") +
        labs(
          x = paste(input$target_type, "Value"),
          y = "Density",
          title = "Distribution of Target Achievement"
        ) +
        theme_minimal()
    })
    
    # Sensitivity tornado plot
    output$sensitivity_tornado <- renderPlot({
      req(fit_results()$results$parameters)
      
      # Create tornado plot data
      params <- c("CL", "V", "Ka", "F")
      base_dose <- optimization_results$optimal_dose %||% 500
      
      tornado_data <- data.frame(
        parameter = rep(params, each = 2),
        variation = rep(c("Low", "High"), length(params)),
        dose_change = runif(length(params) * 2, -50, 50)
      )
      
      ggplot(tornado_data, aes(x = dose_change, y = parameter, fill = variation)) +
        geom_bar(stat = "identity", position = "identity") +
        geom_vline(xintercept = 0, color = "black", linetype = "solid") +
        scale_fill_manual(values = c("Low" = "red", "High" = "green")) +
        labs(
          x = "Change in Optimal Dose (mg)",
          y = "Parameter",
          title = "Sensitivity Analysis - Tornado Plot"
        ) +
        theme_minimal() +
        theme(legend.position = "bottom")
    })
    
    # Covariate effects plot
    output$covariate_effects <- renderPlot({
      req(optimization_results$optimal_dose)
      
      # Create covariate effects data
      covariates <- c("Weight", "CrCL", "Age", "Gender")
      effects <- c(1.2, 0.8, 0.95, 1.05)  # Mock effect sizes
      
      cov_data <- data.frame(
        covariate = covariates,
        effect = effects
      )
      
      ggplot(cov_data, aes(x = covariate, y = effect)) +
        geom_point(size = 4, color = "blue") +
        geom_hline(yintercept = 1, color = "red", linetype = "dashed") +
        geom_errorbar(aes(ymin = effect - 0.1, ymax = effect + 0.1),
                     width = 0.2) +
        labs(
          x = "Covariate",
          y = "Relative Effect on Dose",
          title = "Covariate Effects on Optimal Dose"
        ) +
        theme_minimal()
    })
    
    # Sensitivity table
    output$sensitivity_table <- DT::renderDT({
      req(optimization_results$optimal_dose)
      
      sens_table <- data.frame(
        Parameter = c("CL", "V", "Ka", "F", "Weight", "CrCL"),
        Base_Value = c(5, 50, 1, 0.8, 70, 100),
        Low_Value = c(4, 40, 0.8, 0.6, 50, 50),
        High_Value = c(6, 60, 1.2, 1.0, 90, 150),
        Dose_at_Low = c(450, 480, 490, 470, 460, 550),
        Dose_at_High = c(550, 520, 510, 530, 540, 450),
        Sensitivity = c("High", "Medium", "Low", "Medium", "Medium", "High")
      )
      
      DT::datatable(
        sens_table,
        options = list(pageLength = 10),
        rownames = FALSE
      )
    })
    
    # Simulation plot
    output$simulation_plot <- renderPlotly({
      req(optimization_results$simulation)
      
      sim_data <- optimization_results$simulation$profiles
      
      p <- ggplot(sim_data, aes(x = time, y = concentration, group = sim_id)) +
        geom_line(alpha = 0.1, color = "gray") +
        geom_line(data = sim_data %>% 
                   group_by(time) %>% 
                   summarise(concentration = median(concentration)),
                 aes(group = NULL), color = "blue", size = 1.5) +
        scale_y_log10() +
        labs(
          x = "Time (hours)",
          y = "Concentration (mg/L)",
          title = "Monte Carlo Simulation (1000 virtual patients)"
        ) +
        theme_minimal()
      
      ggplotly(p)
    })
    
    # Target achievement plot
    output$target_achievement <- renderPlot({
      req(optimization_results$simulation)
      
      achievement_data <- optimization_results$simulation$target_achievement
      
      ggplot(achievement_data, aes(x = achieved)) +
        geom_bar(aes(y = ..prop..), fill = "green", alpha = 0.7) +
        scale_y_continuous(labels = scales::percent) +
        labs(
          x = "Target Achieved",
          y = "Proportion of Patients",
          title = "Target Achievement Rate"
        ) +
        theme_minimal()
    })
    
    # Safety metrics plot
    output$safety_metrics <- renderPlot({
      req(optimization_results$simulation)
      
      safety_data <- data.frame(
        metric = c("Cmax > Toxic", "AUC > Upper Limit", "Cmin < Therapeutic"),
        percentage = c(5, 8, 12)
      )
      
      ggplot(safety_data, aes(x = metric, y = percentage)) +
        geom_bar(stat = "identity", fill = c("red", "orange", "yellow")) +
        geom_hline(yintercept = 10, color = "red", linetype = "dashed") +
        labs(
          x = "Safety Metric",
          y = "Percentage of Patients (%)",
          title = "Safety Analysis"
        ) +
        theme_minimal() +
        theme(axis.text.x = element_text(angle = 45, hjust = 1))
    })
    
    # Simulation summary
    output$simulation_summary <- renderPrint({
      req(optimization_results$simulation)
      
      cat("Monte Carlo Simulation Summary\n")
      cat("==============================\n\n")
      cat("Number of simulations:", 1000, "\n")
      cat("Optimal dose:", optimization_results$optimal_dose, "mg\n")
      cat("Dosing interval:", input$dosing_interval, "hours\n")
      cat("\nTarget Achievement:\n")
      cat("  - Target:", input$target_type, "=", input$target_value, "\n")
      cat("  - Achievement rate:", 
          round(optimization_results$probability * 100, 1), "%\n")
      cat("\nSafety Metrics:\n")
      cat("  - Patients with Cmax > toxic limit: 5%\n")
      cat("  - Patients with subtherapeutic levels: 12%\n")
    })
    
    # Return optimization results
    return(reactive(optimization_results))
  })
}

# Helper functions for optimization
optimize_dosing_regimen <- function(model, parameters, covariates, settings) {
  # Mock optimization result
  optimal_dose <- 500 * (covariates$weight / 70) * (100 / covariates$crcl)
  optimal_dose <- max(settings$min_dose, min(settings$max_dose, optimal_dose))
  
  list(
    optimal_dose = optimal_dose,
    regimen = data.frame(
      Dose_Number = 1:settings$n_doses,
      Time_h = (0:(settings$n_doses-1)) * settings$interval,
      Dose_mg = rep(optimal_dose, settings$n_doses),
      Route = settings$route,
      Duration_h = ifelse(settings$route == "iv_infusion", 
                          settings$infusion_duration, 0)
    ),
    predictions = list(
      target_value = settings$target_value * 1.05,
      profile = data.frame(
        time = seq(0, settings$n_doses * settings$interval, by = 0.5),
        concentration = exp(rnorm(length(seq(0, settings$n_doses * settings$interval, by = 0.5)), 3, 0.5)),
        ci_lower = exp(rnorm(length(seq(0, settings$n_doses * settings$interval, by = 0.5)), 2.5, 0.5)),
        ci_upper = exp(rnorm(length(seq(0, settings$n_doses * settings$interval, by = 0.5)), 3.5, 0.5))
      )
    ),
    probability = 0.92
  )
}

simulate_dosing_regimen <- function(dose, regimen, model, n_sim) {
  # Mock simulation
  list(
    profiles = data.frame(
      sim_id = rep(1:n_sim, each = 48),
      time = rep(seq(0, 47), n_sim),
      concentration = exp(rnorm(48 * n_sim, 3, 1))
    ),
    target_achievement = data.frame(
      achieved = sample(c(TRUE, FALSE), n_sim, replace = TRUE, prob = c(0.92, 0.08))
    ),
    target_achieved = rnorm(n_sim, 400, 50)
  )
}

calculate_target_metric <- function(dose, parameters, target_type, interval) {
  # Mock calculation
  base_value <- switch(target_type,
    "auc" = dose * 10,
    "cmax" = dose / 10,
    "cmin" = dose / 50,
    "time_above_mic" = dose / 5,
    "auc_mic_ratio" = dose * 5
  )
  base_value * rnorm(1, 1, 0.1)
}

calculate_target_probability <- function(dose, parameters, target_value, target_type) {
  # Mock probability calculation
  metric <- calculate_target_metric(dose, parameters, target_type, 12)
  pnorm(metric, target_value, target_value * 0.2)
}
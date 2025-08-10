# R/run_fit_jags.R
# PK/PD Analysis using JAGS for Bayesian MCMC Modeling
# Created for modularized Shiny application

# Load required libraries
library(rjags)
library(coda)
library(dplyr)
library(tidyr)

#' Run JAGS fitting for PK/PD models
#'
#' @param data Data frame with columns: ID, TIME, DV, DOSE, optional: AMT, EVID, MDV, Covariates
#' @param config List with model configuration
#' @param progress_callback Optional function for progress updates
#'
#' @return List containing model results, parameters, predictions, and diagnostics
#' @export
run_fit_jags <- function(data, config, progress_callback = NULL) {
  
  # Validate inputs
  validate_inputs(data, config)
  
  # Set default configuration values
  config <- set_default_config(config)
  
  # Update progress
  if (!is.null(progress_callback)) {
    progress_callback("Preparing data for JAGS...")
  }
  
  # Prepare data for JAGS
  jags_data <- prepare_jags_data(data, config)
  
  # Create JAGS model string
  model_string <- create_jags_model(config$model_type, config$error_model, jags_data)
  
  # Create initial values
  inits <- create_initial_values(config, jags_data, data)
  
  # Get parameters to monitor
  parameters <- get_parameters_to_monitor(config$model_type, config$error_model)
  
  # Compile JAGS model
  if (!is.null(progress_callback)) {
    progress_callback("Compiling JAGS model...")
  }
  
  tryCatch({
    model <- jags.model(
      textConnection(model_string),
      data = jags_data,
      inits = inits,
      n.chains = config$n_chains,
      n.adapt = 1000,
      quiet = TRUE
    )
  }, error = function(e) {
    stop(paste("Error compiling JAGS model:", e$message))
  })
  
  # Burn-in phase
  if (!is.null(progress_callback)) {
    progress_callback("Running burn-in phase...")
  }
  
  update(model, config$n_burnin, progress.bar = "none")
  
  # Sample from posterior
  if (!is.null(progress_callback)) {
    progress_callback("Sampling from posterior distribution...")
  }
  
  samples <- coda.samples(
    model,
    variable.names = parameters,
    n.iter = config$n_iter,
    thin = config$n_thin,
    progress.bar = "none"
  )
  
  # Process results
  if (!is.null(progress_callback)) {
    progress_callback("Processing results...")
  }
  
  # Calculate parameter statistics
  param_stats <- calculate_parameter_statistics(samples, config$model_type)
  
  # Generate predictions
  predictions <- calculate_predictions(samples, data, config, jags_data)
  
  # Calculate diagnostics
  diagnostics <- calculate_diagnostics(samples, model, jags_data)
  
  # Return formatted results
  results <- list(
    model = model,
    parameters = param_stats,
    predictions = predictions,
    diagnostics = diagnostics,
    samples = samples,
    config = config,
    data = data
  )
  
  if (!is.null(progress_callback)) {
    progress_callback("Fitting completed successfully!")
  }
  
  return(results)
}

#' Validate input data and configuration
validate_inputs <- function(data, config) {
  # Check required columns in data
  required_cols <- c("ID", "TIME", "DV")
  missing_cols <- setdiff(required_cols, names(data))
  if (length(missing_cols) > 0) {
    stop(paste("Missing required columns in data:", paste(missing_cols, collapse = ", ")))
  }
  
  # Check for dose information
  if (!("DOSE" %in% names(data)) && !("AMT" %in% names(data))) {
    stop("Data must contain either DOSE or AMT column for dosing information")
  }
  
  # Validate model type
  valid_models <- c("one_comp", "two_comp", "three_comp", "one_comp_abs", "two_comp_abs")
  if (!config$model_type %in% valid_models) {
    stop(paste("Invalid model_type. Must be one of:", paste(valid_models, collapse = ", ")))
  }
  
  # Validate error model
  valid_errors <- c("additive", "proportional", "combined")
  if (!config$error_model %in% valid_errors) {
    stop(paste("Invalid error_model. Must be one of:", paste(valid_errors, collapse = ", ")))
  }
}

#' Set default configuration values
set_default_config <- function(config) {
  defaults <- list(
    n_chains = 3,
    n_iter = 10000,
    n_burnin = 5000,
    n_thin = 1,
    adapt = 1000
  )
  
  for (name in names(defaults)) {
    if (is.null(config[[name]])) {
      config[[name]] <- defaults[[name]]
    }
  }
  
  return(config)
}

#' Prepare data for JAGS
prepare_jags_data <- function(data, config) {
  # Handle missing values
  data <- data %>%
    filter(!is.na(DV), !is.na(TIME))
  
  # Get dose information
  if ("DOSE" %in% names(data)) {
    doses <- data$DOSE
  } else if ("AMT" %in% names(data)) {
    # Extract doses from AMT column
    dose_data <- data %>%
      filter(!is.na(AMT), AMT > 0) %>%
      group_by(ID) %>%
      slice(1) %>%
      select(ID, DOSE = AMT)
    
    data <- data %>%
      left_join(dose_data, by = "ID")
    doses <- data$DOSE
  }
  
  # Create numeric ID mapping
  id_map <- data.frame(
    ID_original = unique(data$ID),
    ID_numeric = seq_along(unique(data$ID))
  )
  
  data <- data %>%
    left_join(id_map, by = c("ID" = "ID_original"))
  
  # Prepare JAGS data list
  jags_data <- list(
    N = nrow(data),
    n_subjects = length(unique(data$ID_numeric)),
    ID = data$ID_numeric,
    TIME = data$TIME,
    DV = data$DV,
    DOSE = doses
  )
  
  # Add covariates if present
  covariate_cols <- c("WT", "AGE", "SEX", "CRCL")
  for (cov in covariate_cols) {
    if (cov %in% names(data)) {
      jags_data[[cov]] <- data[[cov]]
    }
  }
  
  return(jags_data)
}

#' Create JAGS model string based on model type and error model
create_jags_model <- function(model_type, error_model, jags_data) {
  
  model_string <- switch(model_type,
    "one_comp" = create_one_comp_model(error_model, jags_data),
    "two_comp" = create_two_comp_model(error_model, jags_data),
    "three_comp" = create_three_comp_model(error_model, jags_data),
    "one_comp_abs" = create_one_comp_abs_model(error_model, jags_data),
    "two_comp_abs" = create_two_comp_abs_model(error_model, jags_data)
  )
  
  return(model_string)
}

#' Create one-compartment IV model
create_one_comp_model <- function(error_model, jags_data) {
  
  # Base model structure
  model_string <- "
model {
  # Likelihood
  for (i in 1:N) {
    "
  
  # Add error model
  if (error_model == "additive") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau)
    pred[i] <- IPRED[i]")
  } else if (error_model == "proportional") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau_prop[i])
    tau_prop[i] <- tau / (pred[i] * pred[i] + 0.0001)
    pred[i] <- IPRED[i]")
  } else if (error_model == "combined") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau_comb[i])
    tau_comb[i] <- 1 / (sigma_add * sigma_add + sigma_prop * sigma_prop * pred[i] * pred[i] + 0.0001)
    pred[i] <- IPRED[i]")
  }
  
  # Add PK model
  model_string <- paste0(model_string, "
    
    # One-compartment model
    IPRED[i] <- (DOSE[i] / V_ind[ID[i]]) * exp(-CL_ind[ID[i]] / V_ind[ID[i]] * TIME[i])
  }
  
  # Individual parameters (log-normal distribution)
  for (j in 1:n_subjects) {
    log_CL_ind[j] ~ dnorm(log_CL_pop, tau_CL)
    log_V_ind[j] ~ dnorm(log_V_pop, tau_V)
    CL_ind[j] <- exp(log_CL_ind[j])
    V_ind[j] <- exp(log_V_ind[j])
  }
  
  # Population parameters
  log_CL_pop ~ dnorm(log(5), 0.5)    # Prior: median ~5 L/h
  log_V_pop ~ dnorm(log(50), 0.5)    # Prior: median ~50 L
  CL_pop <- exp(log_CL_pop)
  V_pop <- exp(log_V_pop)
  
  # Between-subject variability
  tau_CL ~ dgamma(0.01, 0.01)
  tau_V ~ dgamma(0.01, 0.01)
  omega_CL <- 1 / tau_CL
  omega_V <- 1 / tau_V
  ")
  
  # Add error model parameters
  if (error_model == "additive") {
    model_string <- paste0(model_string, "
  # Residual error
  tau <- 1 / (sigma * sigma)
  sigma ~ dunif(0, 10)
}")
  } else if (error_model == "proportional") {
    model_string <- paste0(model_string, "
  # Residual error
  tau <- 1 / (sigma_prop * sigma_prop)
  sigma_prop ~ dunif(0, 1)
  sigma <- sigma_prop  # For compatibility
}")
  } else if (error_model == "combined") {
    model_string <- paste0(model_string, "
  # Residual error
  sigma_add ~ dunif(0, 10)
  sigma_prop ~ dunif(0, 1)
  sigma <- sigma_add  # For compatibility
}")
  }
  
  return(model_string)
}

#' Create two-compartment IV model
create_two_comp_model <- function(error_model, jags_data) {
  
  model_string <- "
model {
  # Likelihood
  for (i in 1:N) {
    "
  
  # Add error model
  if (error_model == "additive") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau)
    pred[i] <- IPRED[i]")
  } else if (error_model == "proportional") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau_prop[i])
    tau_prop[i] <- tau / (pred[i] * pred[i] + 0.0001)
    pred[i] <- IPRED[i]")
  } else if (error_model == "combined") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau_comb[i])
    tau_comb[i] <- 1 / (sigma_add * sigma_add + sigma_prop * sigma_prop * pred[i] * pred[i] + 0.0001)
    pred[i] <- IPRED[i]")
  }
  
  # Add PK model (two-compartment)
  model_string <- paste0(model_string, "
    
    # Two-compartment model
    # Calculate micro-constants
    k10[i] <- CL_ind[ID[i]] / V1_ind[ID[i]]
    k12[i] <- Q_ind[ID[i]] / V1_ind[ID[i]]
    k21[i] <- Q_ind[ID[i]] / V2_ind[ID[i]]
    
    # Calculate hybrid constants
    a[i] <- 0.5 * (k12[i] + k21[i] + k10[i] + sqrt(pow(k12[i] + k21[i] + k10[i], 2) - 4 * k21[i] * k10[i]))
    b[i] <- 0.5 * (k12[i] + k21[i] + k10[i] - sqrt(pow(k12[i] + k21[i] + k10[i], 2) - 4 * k21[i] * k10[i]))
    
    A[i] <- DOSE[i] * (a[i] - k21[i]) / (V1_ind[ID[i]] * (a[i] - b[i]))
    B[i] <- DOSE[i] * (k21[i] - b[i]) / (V1_ind[ID[i]] * (a[i] - b[i]))
    
    IPRED[i] <- A[i] * exp(-a[i] * TIME[i]) + B[i] * exp(-b[i] * TIME[i])
  }
  
  # Individual parameters
  for (j in 1:n_subjects) {
    log_CL_ind[j] ~ dnorm(log_CL_pop, tau_CL)
    log_V1_ind[j] ~ dnorm(log_V1_pop, tau_V1)
    log_Q_ind[j] ~ dnorm(log_Q_pop, tau_Q)
    log_V2_ind[j] ~ dnorm(log_V2_pop, tau_V2)
    
    CL_ind[j] <- exp(log_CL_ind[j])
    V1_ind[j] <- exp(log_V1_ind[j])
    Q_ind[j] <- exp(log_Q_ind[j])
    V2_ind[j] <- exp(log_V2_ind[j])
  }
  
  # Population parameters
  log_CL_pop ~ dnorm(log(5), 0.5)     # Prior: median ~5 L/h
  log_V1_pop ~ dnorm(log(30), 0.5)    # Prior: median ~30 L
  log_Q_pop ~ dnorm(log(3), 0.5)      # Prior: median ~3 L/h
  log_V2_pop ~ dnorm(log(20), 0.5)    # Prior: median ~20 L
  
  CL_pop <- exp(log_CL_pop)
  V1_pop <- exp(log_V1_pop)
  Q_pop <- exp(log_Q_pop)
  V2_pop <- exp(log_V2_pop)
  
  # Between-subject variability
  tau_CL ~ dgamma(0.01, 0.01)
  tau_V1 ~ dgamma(0.01, 0.01)
  tau_Q ~ dgamma(0.01, 0.01)
  tau_V2 ~ dgamma(0.01, 0.01)
  
  omega_CL <- 1 / tau_CL
  omega_V1 <- 1 / tau_V1
  omega_Q <- 1 / tau_Q
  omega_V2 <- 1 / tau_V2
  ")
  
  # Add error model parameters
  if (error_model == "additive") {
    model_string <- paste0(model_string, "
  # Residual error
  tau <- 1 / (sigma * sigma)
  sigma ~ dunif(0, 10)
}")
  } else if (error_model == "proportional") {
    model_string <- paste0(model_string, "
  # Residual error
  tau <- 1 / (sigma_prop * sigma_prop)
  sigma_prop ~ dunif(0, 1)
  sigma <- sigma_prop
}")
  } else if (error_model == "combined") {
    model_string <- paste0(model_string, "
  # Residual error
  sigma_add ~ dunif(0, 10)
  sigma_prop ~ dunif(0, 1)
  sigma <- sigma_add
}")
  }
  
  return(model_string)
}

#' Create three-compartment IV model
create_three_comp_model <- function(error_model, jags_data) {
  # This is a more complex model, simplified implementation
  # In practice, would need full three-compartment equations
  model_string <- create_two_comp_model(error_model, jags_data)
  # Add third compartment parameters and equations
  # This is a placeholder - full implementation would be more complex
  return(model_string)
}

#' Create one-compartment oral absorption model
create_one_comp_abs_model <- function(error_model, jags_data) {
  
  model_string <- "
model {
  # Likelihood
  for (i in 1:N) {
    "
  
  # Add error model
  if (error_model == "additive") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau)
    pred[i] <- IPRED[i]")
  } else if (error_model == "proportional") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau_prop[i])
    tau_prop[i] <- tau / (pred[i] * pred[i] + 0.0001)
    pred[i] <- IPRED[i]")
  } else if (error_model == "combined") {
    model_string <- paste0(model_string, "
    DV[i] ~ dnorm(pred[i], tau_comb[i])
    tau_comb[i] <- 1 / (sigma_add * sigma_add + sigma_prop * sigma_prop * pred[i] * pred[i] + 0.0001)
    pred[i] <- IPRED[i]")
  }
  
  # Add PK model with oral absorption
  model_string <- paste0(model_string, "
    
    # One-compartment model with first-order absorption
    ke[i] <- CL_ind[ID[i]] / V_ind[ID[i]]
    
    # Flip-flop kinetics check
    ka_ke_ratio[i] <- Ka_ind[ID[i]] / ke[i]
    
    # Concentration calculation
    IPRED[i] <- equals(Ka_ind[ID[i]], ke[i]) * 
                (F_ind[ID[i]] * DOSE[i] * Ka_ind[ID[i]] / V_ind[ID[i]]) * TIME[i] * exp(-Ka_ind[ID[i]] * TIME[i]) +
                (1 - equals(Ka_ind[ID[i]], ke[i])) *
                (F_ind[ID[i]] * DOSE[i] * Ka_ind[ID[i]] / (V_ind[ID[i]] * (Ka_ind[ID[i]] - ke[i]))) * 
                (exp(-ke[i] * TIME[i]) - exp(-Ka_ind[ID[i]] * TIME[i]))
  }
  
  # Individual parameters
  for (j in 1:n_subjects) {
    log_CL_ind[j] ~ dnorm(log_CL_pop, tau_CL)
    log_V_ind[j] ~ dnorm(log_V_pop, tau_V)
    log_Ka_ind[j] ~ dnorm(log_Ka_pop, tau_Ka)
    logit_F_ind[j] ~ dnorm(logit_F_pop, tau_F)
    
    CL_ind[j] <- exp(log_CL_ind[j])
    V_ind[j] <- exp(log_V_ind[j])
    Ka_ind[j] <- exp(log_Ka_ind[j])
    F_ind[j] <- exp(logit_F_ind[j]) / (1 + exp(logit_F_ind[j]))
  }
  
  # Population parameters
  log_CL_pop ~ dnorm(log(5), 0.5)     # Prior: median ~5 L/h
  log_V_pop ~ dnorm(log(50), 0.5)     # Prior: median ~50 L
  log_Ka_pop ~ dnorm(log(1), 0.5)     # Prior: median ~1 h^-1
  logit_F_pop ~ dnorm(0, 0.5)         # Prior: F ~0.5 on logit scale
  
  CL_pop <- exp(log_CL_pop)
  V_pop <- exp(log_V_pop)
  Ka_pop <- exp(log_Ka_pop)
  F_pop <- exp(logit_F_pop) / (1 + exp(logit_F_pop))
  
  # Between-subject variability
  tau_CL ~ dgamma(0.01, 0.01)
  tau_V ~ dgamma(0.01, 0.01)
  tau_Ka ~ dgamma(0.01, 0.01)
  tau_F ~ dgamma(0.01, 0.01)
  
  omega_CL <- 1 / tau_CL
  omega_V <- 1 / tau_V
  omega_Ka <- 1 / tau_Ka
  omega_F <- 1 / tau_F
  ")
  
  # Add error model parameters
  if (error_model == "additive") {
    model_string <- paste0(model_string, "
  # Residual error
  tau <- 1 / (sigma * sigma)
  sigma ~ dunif(0, 10)
}")
  } else if (error_model == "proportional") {
    model_string <- paste0(model_string, "
  # Residual error
  tau <- 1 / (sigma_prop * sigma_prop)
  sigma_prop ~ dunif(0, 1)
  sigma <- sigma_prop
}")
  } else if (error_model == "combined") {
    model_string <- paste0(model_string, "
  # Residual error
  sigma_add ~ dunif(0, 10)
  sigma_prop ~ dunif(0, 1)
  sigma <- sigma_add
}")
  }
  
  return(model_string)
}

#' Create two-compartment oral absorption model
create_two_comp_abs_model <- function(error_model, jags_data) {
  # Simplified implementation - would need full equations
  model_string <- create_one_comp_abs_model(error_model, jags_data)
  # Add second compartment
  return(model_string)
}

#' Create initial values for JAGS chains
create_initial_values <- function(config, jags_data, data) {
  
  n_chains <- config$n_chains
  n_subjects <- jags_data$n_subjects
  
  # Function to generate initial values for one chain
  generate_inits <- function() {
    inits <- list()
    
    # Base parameters for all models
    inits$log_CL_pop <- log(runif(1, 2, 10))
    inits$tau_CL <- rgamma(1, 1, 1)
    inits$log_CL_ind <- rnorm(n_subjects, inits$log_CL_pop, 0.1)
    
    if (config$model_type %in% c("one_comp", "one_comp_abs")) {
      inits$log_V_pop <- log(runif(1, 20, 80))
      inits$tau_V <- rgamma(1, 1, 1)
      inits$log_V_ind <- rnorm(n_subjects, inits$log_V_pop, 0.1)
    }
    
    if (config$model_type %in% c("two_comp", "two_comp_abs")) {
      inits$log_V1_pop <- log(runif(1, 20, 50))
      inits$log_V2_pop <- log(runif(1, 10, 40))
      inits$log_Q_pop <- log(runif(1, 1, 5))
      inits$tau_V1 <- rgamma(1, 1, 1)
      inits$tau_V2 <- rgamma(1, 1, 1)
      inits$tau_Q <- rgamma(1, 1, 1)
      inits$log_V1_ind <- rnorm(n_subjects, inits$log_V1_pop, 0.1)
      inits$log_V2_ind <- rnorm(n_subjects, inits$log_V2_pop, 0.1)
      inits$log_Q_ind <- rnorm(n_subjects, inits$log_Q_pop, 0.1)
    }
    
    if (config$model_type %in% c("one_comp_abs", "two_comp_abs")) {
      inits$log_Ka_pop <- log(runif(1, 0.5, 2))
      inits$logit_F_pop <- rnorm(1, 0, 0.5)
      inits$tau_Ka <- rgamma(1, 1, 1)
      inits$tau_F <- rgamma(1, 1, 1)
      inits$log_Ka_ind <- rnorm(n_subjects, inits$log_Ka_pop, 0.1)
      inits$logit_F_ind <- rnorm(n_subjects, inits$logit_F_pop, 0.1)
    }
    
    # Error model parameters
    if (config$error_model == "additive") {
      inits$sigma <- runif(1, 0.1, 2)
    } else if (config$error_model == "proportional") {
      inits$sigma_prop <- runif(1, 0.05, 0.3)
    } else if (config$error_model == "combined") {
      inits$sigma_add <- runif(1, 0.1, 2)
      inits$sigma_prop <- runif(1, 0.05, 0.3)
    }
    
    # Override with user-provided initial values if available
    if (!is.null(config$initial_values)) {
      for (param in names(config$initial_values)) {
        if (param %in% names(inits)) {
          inits[[param]] <- config$initial_values[[param]]
        }
      }
    }
    
    return(inits)
  }
  
  # Generate initial values for each chain
  inits_list <- lapply(1:n_chains, function(i) generate_inits())
  
  return(inits_list)
}

#' Get parameters to monitor based on model type
get_parameters_to_monitor <- function(model_type, error_model) {
  
  # Base parameters for all models
  params <- c("CL_pop", "omega_CL", "CL_ind")
  
  if (model_type == "one_comp") {
    params <- c(params, "V_pop", "omega_V", "V_ind")
  } else if (model_type == "two_comp") {
    params <- c(params, "V1_pop", "V2_pop", "Q_pop", 
                "omega_V1", "omega_V2", "omega_Q",
                "V1_ind", "V2_ind", "Q_ind")
  } else if (model_type == "three_comp") {
    params <- c(params, "V1_pop", "V2_pop", "V3_pop", "Q1_pop", "Q2_pop",
                "omega_V1", "omega_V2", "omega_V3", "omega_Q1", "omega_Q2",
                "V1_ind", "V2_ind", "V3_ind", "Q1_ind", "Q2_ind")
  } else if (model_type == "one_comp_abs") {
    params <- c(params, "V_pop", "Ka_pop", "F_pop",
                "omega_V", "omega_Ka", "omega_F",
                "V_ind", "Ka_ind", "F_ind")
  } else if (model_type == "two_comp_abs") {
    params <- c(params, "V1_pop", "V2_pop", "Q_pop", "Ka_pop", "F_pop",
                "omega_V1", "omega_V2", "omega_Q", "omega_Ka", "omega_F",
                "V1_ind", "V2_ind", "Q_ind", "Ka_ind", "F_ind")
  }
  
  # Add error model parameters
  if (error_model == "additive") {
    params <- c(params, "sigma")
  } else if (error_model == "proportional") {
    params <- c(params, "sigma_prop", "sigma")
  } else if (error_model == "combined") {
    params <- c(params, "sigma_add", "sigma_prop", "sigma")
  }
  
  # Add predictions
  params <- c(params, "IPRED", "pred")
  
  return(params)
}

#' Calculate parameter statistics from MCMC samples
calculate_parameter_statistics <- function(samples, model_type) {
  
  # Combine chains
  combined_samples <- do.call(rbind, samples)
  
  # Get population parameters based on model type
  pop_params <- switch(model_type,
    "one_comp" = c("CL_pop", "V_pop", "omega_CL", "omega_V", "sigma"),
    "two_comp" = c("CL_pop", "V1_pop", "V2_pop", "Q_pop", 
                   "omega_CL", "omega_V1", "omega_V2", "omega_Q", "sigma"),
    "three_comp" = c("CL_pop", "V1_pop", "V2_pop", "V3_pop", "Q1_pop", "Q2_pop",
                     "omega_CL", "omega_V1", "omega_V2", "omega_V3", 
                     "omega_Q1", "omega_Q2", "sigma"),
    "one_comp_abs" = c("CL_pop", "V_pop", "Ka_pop", "F_pop",
                       "omega_CL", "omega_V", "omega_Ka", "omega_F", "sigma"),
    "two_comp_abs" = c("CL_pop", "V1_pop", "V2_pop", "Q_pop", "Ka_pop", "F_pop",
                       "omega_CL", "omega_V1", "omega_V2", "omega_Q", 
                       "omega_Ka", "omega_F", "sigma")
  )
  
  # Calculate statistics for each parameter
  param_stats <- data.frame()
  
  for (param in pop_params) {
    if (param %in% colnames(combined_samples)) {
      param_samples <- combined_samples[, param]
      
      stats <- data.frame(
        Parameter = param,
        Mean = mean(param_samples),
        Median = median(param_samples),
        SD = sd(param_samples),
        SE = sd(param_samples) / sqrt(length(param_samples)),
        CI_2.5 = quantile(param_samples, 0.025),
        CI_97.5 = quantile(param_samples, 0.975),
        stringsAsFactors = FALSE
      )
      
      param_stats <- rbind(param_stats, stats)
    }
  }
  
  # Reset row names
  rownames(param_stats) <- NULL
  
  return(param_stats)
}

#' Calculate predictions from MCMC samples
calculate_predictions <- function(samples, data, config, jags_data) {
  
  # Combine chains
  combined_samples <- do.call(rbind, samples)
  
  # Get IPRED columns
  ipred_cols <- grep("^IPRED\\[", colnames(combined_samples), value = TRUE)
  pred_cols <- grep("^pred\\[", colnames(combined_samples), value = TRUE)
  
  # Prepare prediction data frame
  predictions <- data.frame(
    ID = data$ID,
    TIME = data$TIME,
    PRED = NA,
    IPRED = NA,
    IPRED_CI_2.5 = NA,
    IPRED_CI_97.5 = NA
  )
  
  # Calculate predictions for each observation
  for (i in 1:nrow(data)) {
    if (i <= length(ipred_cols)) {
      ipred_samples <- combined_samples[, ipred_cols[i]]
      pred_samples <- combined_samples[, pred_cols[i]]
      
      predictions$PRED[i] <- mean(pred_samples)
      predictions$IPRED[i] <- mean(ipred_samples)
      predictions$IPRED_CI_2.5[i] <- quantile(ipred_samples, 0.025)
      predictions$IPRED_CI_97.5[i] <- quantile(ipred_samples, 0.975)
    }
  }
  
  return(predictions)
}

#' Calculate model diagnostics
calculate_diagnostics <- function(samples, model, jags_data) {
  
  # Calculate DIC
  dic_result <- tryCatch({
    dic.samples(model, n.iter = 1000, type = "pD")
  }, error = function(e) {
    list(deviance = NA, penalty = NA, penalized.deviance = NA)
  })
  
  # Calculate Rhat (Gelman-Rubin statistic)
  rhat_result <- tryCatch({
    gelman.diag(samples, multivariate = FALSE)
  }, error = function(e) {
    list(psrf = data.frame(Point.est. = NA))
  })
  
  # Extract Rhat values for each parameter
  rhat_values <- rhat_result$psrf[, "Point est."]
  
  # Create diagnostics list
  diagnostics <- list(
    DIC = sum(dic_result$deviance) + sum(dic_result$penalty),
    pD = sum(dic_result$penalty),
    Rhat = rhat_values,
    n_subjects = jags_data$n_subjects,
    n_observations = jags_data$N,
    convergence = all(rhat_values < 1.1, na.rm = TRUE)
  )
  
  return(diagnostics)
}

#' Helper function to handle BLQ (Below Limit of Quantification) data
handle_blq_data <- function(data, lloq = NULL) {
  if (is.null(lloq)) {
    # Estimate LLOQ as minimum non-zero value
    lloq <- min(data$DV[data$DV > 0], na.rm = TRUE)
  }
  
  # Flag BLQ observations
  data$BLQ <- data$DV < lloq
  
  # Option 1: Impute as LLOQ/2
  data$DV[data$BLQ] <- lloq / 2
  
  # Option 2: Could also use M3 method (censored likelihood)
  # This would require modification of the JAGS model
  
  return(data)
}

#' Add covariate effects to the model
add_covariate_effects <- function(model_string, covariates) {
  # This function would modify the model string to include covariate effects
  # Example: CL = CL_pop * (WT/70)^0.75 * exp(eta_CL)
  # Implementation depends on specific covariate relationships
  return(model_string)
}

#' Parallel processing for multiple chains
run_parallel_chains <- function(data, config, progress_callback = NULL) {
  # Use parallel package to run chains in parallel
  # This would require additional setup and configuration
  # Currently using sequential processing in main function
  return(NULL)
}
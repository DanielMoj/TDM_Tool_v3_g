# R/joint.R
# Joint-like coupling: PK CL vs. Creatinine (Cr) observations as soft constraint

# Simple CrCL estimate from creatinine (mg/dL), age, weight, sex (Cockcroft-Gault)
cg_crcl <- function(age, weight, sex, scr_mgdl) {
  crcl <- ((140 - age) * weight) / (72 * scr_mgdl)
  if (tolower(sex) == "female") crcl <- 0.85 * crcl
  crcl
}

# Log-likelihood penalty for mismatch between CL and CrCL-derived expectation:
# log(CL) ~ a + b * log(CrCL) with sigma_pen (fixed)
cl_creatinine_penalty <- function(CL, age, weight, sex, creatinine_data, a = log(0.06), b = 1.0, sigma_pen = 0.5) {
  if (is.null(creatinine_data) || nrow(creatinine_data) == 0) return(0)
  crcl_vals <- cg_crcl(age, weight, sex, creatinine_data$creat_mgdl)
  mu <- a + b * log(pmax(crcl_vals, 1))
  # Use the mean across observations as expectation (demo)
  target <- mean(mu)
  dnorm(log(CL), mean = target, sd = sigma_pen, log = TRUE)
}

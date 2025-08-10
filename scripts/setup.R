# scripts/setup.R
# Bootstrap renv and install required packages
if (!requireNamespace("renv", quietly = TRUE)) install.packages("renv")
renv::init(bare = TRUE)
pkgs <- c(
  "shiny","bslib","ggplot2","dplyr","DT","jsonlite","glue","readr","tibble","lubridate",
  "deSolve","numDeriv","MASS","rmarkdown","promises","future"
)
renv::install(pkgs)
renv::snapshot(prompt = FALSE)
message("renv setup complete.")

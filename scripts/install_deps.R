
# Install recommended deps for testing
pkgs <- c("testthat","shinytest2","httr2","yaml","sodium","digest","DBI","RPostgres","cmdstanr","posterior","plumber","processx","covr")
to_install <- setdiff(pkgs, rownames(installed.packages()))
if (length(to_install)) install.packages(to_install)
message("Installed/ensured: ", paste(pkgs, collapse=", "))

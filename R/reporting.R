# R/reporting.R
# Helper to render the PDF report with parameters and return a file path.
render_report_pdf <- function(rmd = "report/report.Rmd", output_file = NULL, params = list()) {
  if (!requireNamespace("rmarkdown", quietly = TRUE)) stop("rmarkdown nicht installiert.")
  if (is.null(output_file)) {
    output_file <- tempfile(fileext = ".pdf")
  }
  out <- rmarkdown::render(
    input = rmd,
    output_format = rmarkdown::pdf_document(),
    output_file = output_file,
    params = params,
    envir = new.env(parent = globalenv()),
    quiet = TRUE
  )
  out
}

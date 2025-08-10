
# api/plumber_phase5.R
# Additional endpoints for FHIR and antibiogram ingestion
#* @apiTitle TDMx Phase5 Add-on
#* @apiDescription FHIR fetch & antibiogram ingest
#* FHIR Observations fetch
#* @param base_url:string
#* @param patient_id:string
#* @param codes:array LOINC codes (comma-separated) e.g. 20578-1,XXXX
#* @param token:string optional bearer
#* @get /ehr/fhir/observations
function(base_url, patient_id, codes = "", token = "") {
  codes_vec <- strsplit(codes, ",")[[1]]; codes_vec <- trimws(codes_vec[nzchar(codes_vec)])
  b <- fhir_get_observations(base_url, patient_id, codes_vec, token = token)
  df <- fhir_observations_to_tdm(b)
  list(n = nrow(df), items = df)
}
#* Upload antibiogram CSV
#* @param path:string path to CSV inside container
#* @post /lis/antibiogram/upload
function(path) {
  df <- read_antibiogram_csv(path)
  list(ok = TRUE, n = nrow(df))
}


#* List drugs from antibiogram DB
#* @get /lis/antibiogram/list
function() {
  con <- connect_pg(); on.exit(try(DBI::dbDisconnect(con), silent = TRUE))
  list(drugs = db_list_antibiogram_drugs(con))
}

#* Get antibiogram distribution for a drug
#* @param drug:string
#* @get /lis/antibiogram/get
function(drug) {
  con <- connect_pg(); on.exit(try(DBI::dbDisconnect(con), silent = TRUE))
  df <- db_get_antibiogram(con, drug)
  list(n = nrow(df), items = df)
}

#* Import CSV into antibiogram DB
#* @param path:string
#* @param source:string
#* @post /lis/antibiogram/import
function(path, source = "api-upload") {
  res <- antibiogram_import_to_db(path, source = source)
  res
}

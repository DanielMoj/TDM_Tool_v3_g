
test_that("password hashing and verify works; audit chain verifies", {
  load_sources()
  skip_if_not_installed("sodium")
  h <- password_hash("secret123")
  expect_true(password_verify("secret123", h))
  # Audit
  td <- make_temp_dir()
  f <- file.path(td, "audit.csv")
  for (i in 1:3) audit_append_hashchain(file=f, actor="tester", action=paste0("act",i), payload=list(i=i))
  expect_true(audit_verify_chain(f))
})

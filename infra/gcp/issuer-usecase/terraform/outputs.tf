output "ci_service_account_email" {
  description = "cf-sts rule `principal` (policy/gcp/<project>/sa-ci/...)."
  value       = google_service_account.ci.email
}

output "github_workload_identity_provider" {
  description = "Use as `workload_identity_provider` in google-github-actions/auth."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "spiffe_workload_identity_provider" {
  description = "Audience for the STS token exchange: //iam.googleapis.com/<this>."
  value       = try(google_iam_workload_identity_pool_provider.spiffe[0].name, null)
}

output "spiffe_principal_prefix" {
  description = "Prefix of the WIF principal for SPIFFE workloads; append subject/<spiffe-id> (cf-sts `principal` for the WIF path)."
  value       = try("principal://iam.googleapis.com/${google_iam_workload_identity_pool.spiffe[0].name}/subject/", null)
}

output "project_number" {
  value = data.google_project.this.number
}

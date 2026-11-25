############################################
# GCP identity for the cf-sts `gcp` issuer
# CI (GitHub Actions or a SPIFFE workload) federates into GCP via Workload Identity Federation,
# impersonates one service account, mints a Google ID token (aud cf-sts, email included) and
# exchanges it at cf-sts for a short-lived Cloudflare token.
############################################

data "google_project" "this" {}

resource "google_service_account" "ci" {
  account_id   = var.sa_account_id
  display_name = "cf-sts GCP issuer usecase CI"
}

# --- GitHub Actions -> WIF ---------------------------------------------------

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "cf-sts-github"
  display_name              = "cf-sts GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-actions"
  display_name                       = "GitHub Actions OIDC"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.ref"              = "assertion.ref"
  }

  # Always restrict pool admission.
  attribute_condition = "assertion.repository_owner == '${var.github_org}'"
}

resource "google_service_account_iam_member" "github" {
  for_each = toset(var.github_repositories)

  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${each.value}"
}

# --- SPIFFE/SPIRE -> WIF (optional) ------------------------------------------

resource "google_iam_workload_identity_pool" "spiffe" {
  count = var.enable_spiffe ? 1 : 0

  workload_identity_pool_id = "cf-sts-spiffe"
  display_name              = "cf-sts SPIFFE"
}

resource "google_iam_workload_identity_pool_provider" "spiffe" {
  count = var.enable_spiffe ? 1 : 0

  workload_identity_pool_id          = google_iam_workload_identity_pool.spiffe[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "spire-oidc"
  display_name                       = "SPIRE OIDC discovery"

  oidc {
    issuer_uri        = var.spiffe_issuer_uri
    allowed_audiences = var.spiffe_allowed_audiences
  }

  attribute_mapping = {
    "google.subject" = "assertion.sub" # the SPIFFE ID
  }
}

resource "google_service_account_iam_member" "spiffe" {
  for_each = var.enable_spiffe ? toset(var.spiffe_ids) : toset([])

  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.spiffe[0].name}/subject/${each.value}"
}

# Required for the SA to mint ID tokens for itself (generateIdToken) when impersonated.
resource "google_service_account_iam_member" "self_token_creator" {
  service_account_id = google_service_account.ci.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.ci.email}"
}

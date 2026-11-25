variable "project_id" {
  description = "Project that hosts the CI service account and the Workload Identity pools."
  type        = string
  default     = "example-project"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "sa_account_id" {
  description = "Service account CI impersonates. Its email is the cf-sts rule `principal` (JWT `email`)."
  type        = string
  default     = "sa-ci"
}

variable "github_org" {
  description = "GitHub org admitted by the GitHub provider attribute condition."
  type        = string
  default     = "example"
}

variable "github_repositories" {
  description = "owner/repo values allowed to impersonate the SA via GitHub OIDC."
  type        = list(string)
  default     = ["example/example-repo"]
}

variable "enable_spiffe" {
  description = "Also create a SPIFFE/SPIRE Workload Identity pool + provider."
  type        = bool
  default     = true
}

variable "spiffe_issuer_uri" {
  description = "SPIRE OIDC discovery provider URL. Must be publicly reachable by Google (or fronted by a trusted endpoint)."
  type        = string
  default     = "https://oidc-discovery.example.com"
}

variable "spiffe_allowed_audiences" {
  description = "Audiences accepted from SPIFFE JWT-SVIDs by the WIF provider (the STS exchange audience, not cf-sts)."
  type        = list(string)
  default     = ["gcp-wif"]
}

variable "spiffe_ids" {
  description = "Exact SPIFFE IDs allowed to impersonate the SA."
  type        = list(string)
  default     = ["spiffe://example.com/ci/deployer"]
}

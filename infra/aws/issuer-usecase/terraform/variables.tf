variable "region" {
  description = "Region used by the provider and by CI for sts:GetWebIdentityToken (a regional call, not available on the global STS endpoint)."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name of the IAM user CI authenticates as. Its ARN is the cf-sts rule `principal` (confirm the real JWT sub)."
  type        = string
  default     = "cf-sts-aws-usecase-ci"
}

variable "enable_outbound_federation" {
  description = "Enable IAM outbound identity federation for the account (account-wide). Set false if it is already enabled or owned by another stack."
  type        = bool
  default     = true
}

variable "audience" {
  description = "Global cf-sts audience (policy/config.yaml). The IAM policy only allows tokens for this audience."
  type        = string
  default     = "cf-sts.example.com"
}

variable "allowed_source_cidrs" {
  description = "Optional: deny use of the key from outside these CIDRs (runner egress). Empty = no IP restriction."
  type        = list(string)
  default     = []
}

variable "tags" {
  type = map(string)
  default = {
    Project = "cloudflare-sts"
    Purpose = "aws-issuer-usecase"
    Owner   = "owner@example.com"
    Managed = "terraform"
  }
}

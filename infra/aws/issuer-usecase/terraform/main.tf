############################################
# AWS identity for the cf-sts `aws` issuer
# CI authenticates as this IAM user (static key kept in GitHub secrets), then asks AWS STS for a
# signed web identity JWT for itself and exchanges it at cf-sts for a short-lived Cloudflare token.
############################################

data "aws_caller_identity" "current" {}

# IAM outbound identity federation (account-wide): gives the account an issuer URL and enables
# sts:GetWebIdentityToken for IAM principals.
resource "aws_iam_outbound_web_identity_federation" "this" {
  count = var.enable_outbound_federation ? 1 : 0
}

resource "aws_iam_user" "ci" {
  name = var.name
  path = "/service/"
}

# Only tokens for the cf-sts audience, nothing else.
data "aws_iam_policy_document" "web_identity" {
  statement {
    sid       = "GetWebIdentityTokenForCfSts"
    actions   = ["sts:GetWebIdentityToken"]
    resources = ["*"]

    # The audience is a list in the request, so the multi-valued set operator is required.
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "sts:IdentityTokenAudience"
      values   = [var.audience]
    }
  }

  # Optional: refuse use of the key from anywhere except known runner egress CIDRs.
  dynamic "statement" {
    for_each = length(var.allowed_source_cidrs) > 0 ? [1] : []

    content {
      sid       = "DenyOutsideKnownEgress"
      effect    = "Deny"
      actions   = ["*"]
      resources = ["*"]

      condition {
        test     = "NotIpAddress"
        variable = "aws:SourceIp"
        values   = var.allowed_source_cidrs
      }
    }
  }
}

resource "aws_iam_user_policy" "web_identity" {
  name   = "get-web-identity-token"
  user   = aws_iam_user.ci.name
  policy = data.aws_iam_policy_document.web_identity.json
}

# The access key is intentionally NOT created here: Terraform would store the secret in state.
# Create it once and store it as GitHub secrets (see docs/issuers/aws.md):
#   aws iam create-access-key --user-name <name>

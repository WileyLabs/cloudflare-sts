output "issuer_identifier" {
  description = "Issuer URL of the account for cf-sts policy/issuers.yaml (aws.iss). JWKS is <issuer>/.well-known/jwks.json (verify)."
  value       = try(aws_iam_outbound_web_identity_federation.this[0].issuer_identifier, null)
}

output "ci_user_arn" {
  description = "ARN of the CI identity. Candidate for the cf-sts rule `principal` (confirm the real JWT `sub`)."
  value       = aws_iam_user.ci.arn
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "create_access_key_command" {
  description = "Run once, then store the output as GitHub secrets. Never commit it."
  value       = "aws iam create-access-key --user-name ${aws_iam_user.ci.name}"
}

# AWS issuer usecase (infra)

Identity for the `aws` issuer of cf-sts. CI authenticates as one IAM user (static key kept in GitHub secrets),
asks AWS STS for a signed web identity JWT for itself (`sts:GetWebIdentityToken`, aud `cf-sts.example.com`),
and exchanges it at cf-sts for a short-lived Cloudflare token.

| Path | What |
|---|---|
| `terraform/` | IAM user `cf-sts-aws-usecase-ci` + inline policy (GetWebIdentityToken for the cf-sts audience, optional source-IP deny), IAM outbound identity federation |

The access key is not created by Terraform (it would land in state). Policy: `policy/aws/123456789012/user/`.
CI: `.github/actions/issuer-usecase/aws`, `scripts/ci/fetch-aws-jwt.sh`. Enable steps: [docs/issuers/aws.md](../../../docs/issuers/aws.md).

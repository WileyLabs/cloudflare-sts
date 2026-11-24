# AWS (IAM outbound identity federation)

| | |
|-|-|
| provider | `aws` |
| iss / JWKS | `policy/issuers.yaml` → `aws` (account issuer URL from `terraform output issuer_identifier`) |
| path | `policy/aws/<account-id>/<resource>[/<principal-slug>]/policy.yaml` |
| principal | exact JWT `sub` (no `*`) |
| JWT source | `sts:GetWebIdentityToken` (regional call, audience `cf-sts.example.com`, RS256) |

An AWS role gets a short-lived signed JWT for itself, so no EKS, Cognito or long-lived key is needed. The IAM policy
of the caller should allow `sts:GetWebIdentityToken` only for the cf-sts audience.

Example for EKS IRSA instead: [../examples/policy/aws/123456789012/eks/cf-sts-client/policy.yaml](../examples/policy/aws/123456789012/eks/cf-sts-client/policy.yaml)

## Usecase (CI identity)

Infra: [`infra/aws/issuer-usecase/`](../../infra/aws/issuer-usecase/) (account `123456789012` example, `us-east-1`). It creates one IAM user,
`cf-sts-aws-usecase-ci`, allowed only `sts:GetWebIdentityToken` for the cf-sts audience, and enables IAM outbound identity federation.

| Identity | Policy |
|-|-|
| IAM user `cf-sts-aws-usecase-ci` (static key in repo secrets) | `policy/aws/123456789012/user/cf-sts-aws-usecase-ci/` |

CI: `.github/actions/issuer-usecase/aws` loads the key (`aws-actions/configure-aws-credentials`), fetches the JWT with
`scripts/ci/fetch-aws-jwt.sh` (`jwt-command`), mints via the `cloudflare-sts` action, lists DNS, then revokes. The only standing
secret is the AWS key; Cloudflare credentials stay short-lived. `ci.yml` and `cd.yml` run it with `allow_no_rule: 'true'` until the steps below are done.

### Enable (in order)

1. Apply `infra/aws/issuer-usecase/terraform` (account-wide outbound federation, IAM user). Note `issuer_identifier` and `ci_user_arn`.
2. Create the key once and store it as repo secrets `CF_STS_AWS_ACCESS_KEY_ID` and `CF_STS_AWS_SECRET_ACCESS_KEY` (never in Git or tickets):
   `aws iam create-access-key --user-name cf-sts-aws-usecase-ci`
3. `aws.iss` / `aws.jwks` in `policy/issuers.yaml` come from `issuer_identifier` (done for account 123456789012; JWKS at `<issuer>/.well-known/jwks.json`).
4. Confirm the exact `sub` of the identity and put it in the policy file:
   `aws sts get-web-identity-token --region us-east-1 --audience cf-sts.example.com --signing-algorithm RS256`
5. `npm run build:policy && npm run verify:policy`, merge, let CD deploy.
6. Flip `allow_no_rule` to `'false'` for the aws job in `ci.yml` and `cd.yml`.
7. Negative tests: another AWS identity gets `403 no_matching_rule`; extra permissions get `permission_not_allowed`.

Rotate the key like any static secret (create the second key, update the secrets, delete the old one). Set `allowed_source_cidrs`
in Terraform to deny the key from outside the runner egress ranges.

Verify on first run: the `sub` format for an IAM user.

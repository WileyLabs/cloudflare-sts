# GCP issuer usecase (infra) — EXAMPLE

Example identity for the `gcp` issuer of cf-sts. CI federates into GCP with Workload Identity Federation
(GitHub Actions OIDC, optionally a SPIFFE/SPIRE JWT-SVID), impersonates one service account, mints a Google
ID token (`aud` cf-sts, `email` included) and exchanges it at cf-sts for a short-lived Cloudflare token.
No static keys anywhere.

| Path | What |
|---|---|
| `terraform/` | SA `sa-ci`, GitHub WIF pool/provider (org-restricted), optional SPIFFE WIF pool/provider, `workloadIdentityUser` bindings |

Replace every `example` value (project, org, repos, SPIFFE IDs, issuer URL) before use.
Policy: `policy/gcp/example-project/sa-ci/`, WIF example `docs/examples/policy/gcp/example-project/wif/`.
Issuer docs: [docs/issuers/gcp.md](../../../docs/issuers/gcp.md). SPIRE side: [../../spiffe/issuer-usecase](../../spiffe/issuer-usecase/README.md).

```bash
cd terraform && terraform init && terraform plan -var project_id=my-project
```

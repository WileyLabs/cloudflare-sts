# GCP (SA + SPIFFE→WIF)

| | |
|-|-|
| provider | `gcp` |
| iss | `https://accounts.google.com` **and** `accounts.google.com` (rules expand to both) |
| JWKS | `https://www.googleapis.com/oauth2/v3/certs` |
| path | `policy/gcp/<project>/<resource>[/<principal-slug>]/policy.yaml` |
| principal | SA email (`*.iam.gserviceaccount.com`, `developer` / `appspot` defaults) or `principal://…` (JWT `email`) |

Verifier requires `email_verified: true` — do not put it in rule `claims`.

```bash
gcloud auth print-identity-token --audiences=cf-sts.example.com --include-email
```

Impersonate a dedicated SA:

```bash
gcloud auth print-identity-token \
  --impersonate-service-account=sa-ci@example-project.iam.gserviceaccount.com \
  --audiences=cf-sts.example.com \
  --include-email
```

Requires `roles/iam.serviceAccountTokenCreator` on that SA.

GitHub→WIF: `google-github-actions/auth` with `token_format: id_token`, `id_token_audience: cf-sts.example.com`, `id_token_include_email: true`. Grant `roles/iam.workloadIdentityUser` first.

Examples: [SA](../examples/policy/gcp/example-infra/cf-lists-manager/policy.yaml) · [WIF](../examples/policy/gcp/example-project/wif/spiffe-helper/policy.yaml) · shipped demo `policy/gcp/example-project/sa-ci/cf-sts-ci/`.

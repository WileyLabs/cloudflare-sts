# Cloudflare STS

## Description

Exchanges the job GitHub OIDC token for a short-lived, scoped Cloudflare API token through the [cf-sts](https://github.com/WileyLabs/cloudflare-sts) Worker, exports it as `CLOUDFLARE_API_TOKEN`, and **revokes it when the job ends**, even if the job fails or is cancelled.

It is a JavaScript action (`node24`, a single dependency-free file, nothing to build) because only JavaScript and Docker actions can run a `post` step. `index.mjs` runs twice: the main step mints the token, and the post step (`post-if: always()`) revokes it. Callers need no cleanup step.

## Inputs

| Name          | Description                                                                                               | Required | Default                            |
| ------------- | --------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------- |
| `url`         | cf-sts base URL                                                                                           | No       | `https://cf-sts.example.com` |
| `audience`    | OIDC audience cf-sts expects                                                                              | No       | `cf-sts.example.com`         |
| `ttl-seconds` | Requested lifetime, 60-86400, capped by the rule `max_ttl_seconds`                                        | No       | `600`                              |
| `permissions` | Only these permission names (comma or newline separated), narrowing what the rule grants, e.g. `DNS Read` | No       | everything the rule grants         |
| `jwt-command` | Shell command that prints a fresh OIDC JWT. Mint and revoke each run it. If empty, uses GitHub Actions OIDC | No       | GitHub OIDC                        |

## Outputs

| Name         | Description                         |
| ------------ | ----------------------------------- |
| `token`      | The Cloudflare API token (masked)   |
| `token-id`   | The Cloudflare token id             |
| `expires-on` | Token expiry (RFC 3339)             |
| `rule`       | The cf-sts policy rule that matched |

## Permissions

- **`id-token: write`**: required when using GitHub OIDC (default). Not required if `jwt-command` supplies the JWT (GCP / SPIFFE).

The caller must match a cf-sts policy rule for that issuer, otherwise mint fails with `no_matching_rule`.

## Usage

### GitHub Actions OIDC (default)

```yaml
jobs:
  example:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: WileyLabs/cloudflare-sts/action@v0.0.1
        with:
          ttl-seconds: 300
          permissions: DNS Read

      - run: |
          curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            "https://api.cloudflare.com/client/v4/zones?name=example.com"
      # Post step revokes the token when the job ends.
```

### GCP WIF (Google ID token)

```yaml
- uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: projects/…/workloadIdentityPools/github/providers/github-actions
    service_account: sa-ci@example-project.iam.gserviceaccount.com
- uses: google-github-actions/setup-gcloud@v2
- uses: WileyLabs/cloudflare-sts/action@v0.0.1
  with:
    jwt-command: gcloud auth print-identity-token --audiences=cf-sts.example.com --include-email
    permissions: DNS Read
```

### SPIFFE / SPIRE

```yaml
- uses: WileyLabs/cloudflare-sts/action@v0.0.1
  with:
    jwt-command: >
      spire-agent api fetch jwt -audience cf-sts.example.com
      -socketPath /spiffe-workload-api/spire-agent.sock
      | awk '{ for (i=1;i<=NF;i++) if ($i ~ /^eyJ/) { print $i; exit } }'
    permissions: DNS Read
```

## Notes

- A failed revoke only logs a warning: the token still expires on its own. If the runner is killed the post step cannot run, so keep the TTL short.
- Each OIDC JWT is single use on the cf-sts side, so mint and revoke each request a fresh one (`jwt-command` is re-run on post).
- Errors print only the HTTP status and the cf-sts error code. The token and the JWT are masked.
- Requires a runner that supports `node24` actions.

## Tests

```bash
node --test action/test/cloudflare-sts.test.mjs
```

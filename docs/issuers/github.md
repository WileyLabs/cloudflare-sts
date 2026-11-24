# GitHub Actions OIDC

| | |
|-|-|
| provider | `github` |
| iss / JWKS | `https://token.actions.githubusercontent.com` (+ `/.well-known/jwks`) |
| path | `policy/github/<org>/<repo>[/<principal-slug>]/policy.yaml` |
| principal | exact OIDC `sub` (no `*`); list = OR |
| claims | optional (`job_workflow_ref`, `environment`, …) |

```yaml
permissions: { id-token: write, contents: read }
steps:
  - uses: WileyLabs/cloudflare-sts/action@TAG
    with: { ttl-seconds: 300 }
```

Example: [../examples/policy/github/example/example-repo/ref-main/policy.yaml](../examples/policy/github/example/example-repo/ref-main/policy.yaml)

Shipped demos under `policy/github/example/`: `cloudflare-sts/ci-usecase`, `cloudflare-sts/environment-production`, `example-app`.

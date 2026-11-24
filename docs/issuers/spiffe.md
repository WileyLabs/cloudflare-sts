# SPIFFE / SPIRE

| | |
|-|-|
| provider | `spiffe` |
| iss / JWKS | `https://oidc-discovery.example.com` (+ `/keys`) |
| path | `policy/spiffe/<trust-domain>/<resource>[/<principal-slug>]/policy.yaml` |
| principal | `spiffe://…` (JWT `sub`); path-segment `*` ok; no bare `*` |

JWT-SVIDs may omit `iss`; cf-sts binds via trust domain in `sub` to the configured SPIFFE JWKS. When `iss` is present it must match.

```bash
spire-agent api fetch jwt -audience cf-sts.example.com \
  -socketPath /spiffe-workload-api/spire-agent.sock
```

CI smoke skips if the agent socket is missing; soft-skips `unknown_issuer` until production has SPIFFE enabled.

Example: [../examples/policy/spiffe/example.com/x509pop-agent/spiffe-helper/policy.yaml](../examples/policy/spiffe/example.com/x509pop-agent/spiffe-helper/policy.yaml)
